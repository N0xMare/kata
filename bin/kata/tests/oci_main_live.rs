//! The oci-MAIN live corpus: a durable installed `kata` main running the `oci`
//! execution profile drives real certified-container cells against shipped packs and
//! hand-built fixtures, asserted from OUTSIDE kata — raw ledger reads, `git` on the
//! fixture repository, the pinned youki's own `list`, cgroup and process censuses.
//!
//! The cells — kill/settle, wall-clock, workspace-effect, invocation-param, cancel,
//! reuse, isolated-base-head, fan-in and real-container — share one installed-main
//! harness.
//!
//! # Why durable mains
//!
//! The production shape: the capsule route resolves every id through `<data_dir>`'s
//! planes opened from disk, and a workflow runs only on an installed main — `kata
//! run` has no daemon-free face. The mains run ONE AT A TIME: an installed main holds
//! the per-user discovery lease.
//!
//! # Host preconditions (a skip is a failure; each one FAILS naming itself)
//!
//! The `oci` side runs under `systemd-run --user --scope -p Delegate=yes` with
//! `kata-provider-youki` provisioned into a scratch by-hash store — the same certified
//! route every OCI live cell uses, selected by the `oci` execution profile alone — and
//! binds the busybox
//! busybox and `getent` closures below, which must be realised in the host's Nix store
//! (`nix build --no-link --print-out-paths nixpkgs#pkgsStatic.busybox
//! nixpkgs#pkgsStatic.getent`). Build the provider first:
//! `cargo build -p kata-provider-youki --bin kata-provider-youki`.

#![cfg(target_os = "linux")]

use kata_test_utils::git::hermetic_git_in;
use kata_test_utils::own_main::{ChildState, await_own_main};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The statically linked busybox closure the OCI live cells bind.
const BUSYBOX: &str =
    "/nix/store/qddzvnv6b0805nkvbqddbswddcfhx814-busybox-static-x86_64-unknown-linux-musl-1.37.0";

/// The statically linked NetBSD `getent` the smoke invokes — busybox has no such applet.
const GETENT: &str = "/nix/store/shwr4cipfr4ypvi7vjr20y4k6ziyzkqy-getent-getent-netbsd-static-x86_64-unknown-linux-musl-9.2";

/// The git closure the `requires = ["git"]` cell binds. `pkgsStatic.gitMinimal`
/// does NOT build on this host — `nix build nixpkgs#pkgsStatic.gitMinimal`
/// compiles musl coreutils/gawk/gnused/zlib-ng from source with no substitution
/// — so the DYNAMIC `nixpkgs#gitMinimal` root is pinned the way `GETENT` is;
/// `store_paths` expands it to its full 34-path closure
/// (`nix path-info --recursive`) when the node declares its environment.
const GIT_MINIMAL: &str = "/nix/store/3ba67bl61l0dxp1x4m9waqnvm5n5bkcs-git-minimal-2.55.0";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("bin/kata has a grandparent")
        .to_path_buf()
}

/// The CLI under test, from the checkout. The subworkflow cell's parent names its
/// child, a `workflows/smoke` rig, which neither a bundle nor a checkout build
/// resolves: the explicit stdlib dir opens its `smoke` sibling, here and in
/// [`Main::start`].
fn kata() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kata"));
    command
        .current_dir(repo_root())
        .env("KATA_STDLIB_DIR", repo_root().join("workflows/std"));
    command
}

fn write_config(root: &Path, profile: &str) -> PathBuf {
    write_config_with_programs(root, profile, &[])
}

/// `write_config` whose oci node environment also binds each extra store path's
/// closure and prepends its `bin/` to the environment PATH — the door a
/// `sandbox_profile(requires = [..])` is judged against.
fn write_config_with_programs(root: &Path, profile: &str, extra_store_paths: &[&str]) -> PathBuf {
    let data_dir = root.join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let environment = if profile == "oci" {
        let mut paths: Vec<&str> = vec![BUSYBOX, GETENT];
        paths.extend(extra_store_paths.iter().copied());
        let store_paths = paths
            .iter()
            .map(|path| format!("\"{path}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let path_prepend = paths
            .iter()
            .map(|path| format!("\"{path}/bin\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "environment = {{ label = \"busybox-getent\", system = \"x86_64-linux\", \
             nixpkgs_attribute = \"nixpkgs#pkgsStatic.busybox\", store_paths = [{store_paths}], \
             path_prepend = [{path_prepend}], integrity_policy = {{ verify = \"nar_hash_only\", sigs_needed \
             = 0, required_signers = [], allow_unsigned_content_addressed = true, \
             verify_contents_at_declare = true }} }}\n"
        )
    } else {
        String::new()
    };
    let path = root.join("kata.toml");
    std::fs::write(
        &path,
        format!(
            "[node]\nid = \"differential-{profile}\"\ndata_dir = \"{data}\"\n{environment}\n[workers]\ndispatch_deadline_ms = 30000\n\
             heartbeat_interval_ms = 1000\nheartbeat_grace_ms = 5000\nmax_workers = 4\n\
             transports = [{{ type = \"supervised_node\" }}]\n\n[api]\nbind = \"127.0.0.1:0\"\n\
             auth = {{ type = \"disabled\" }}\n\n[agents.shell]\n",
            data = data_dir.display(),
        ),
    )
    .unwrap();
    path
}

/// Provision the freshly built `kata-provider-youki` into a scratch by-hash store and
/// return the three exports the route reads, with the guard that unseals the store.
///
/// The store is sealed `0500`, which the owning `TempDir`'s removal cannot get
/// through, so a caller binds the guard AFTER that `TempDir` and it drops FIRST —
/// on a panic too. See `kata_worker::UnsealOnDrop`.
fn provision_provider(root: &Path) -> (Vec<(String, String)>, kata_worker::UnsealOnDrop) {
    let built = PathBuf::from(env!("CARGO_BIN_EXE_kata")).with_file_name("kata-provider-youki");
    assert!(
        built.is_file(),
        "{} is absent: run `cargo build -p kata-provider-youki --bin kata-provider-youki`",
        built.display()
    );
    let source = root.join("provider-src");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::copy(&built, source.join("kata-provider-youki")).unwrap();
    let store = root.join("provider-store");
    let unseal = kata_worker::UnsealOnDrop::new(&store);
    let output = kata()
        .env("KATA_EXTERNAL_PROVIDER_STORE", &store)
        .args(["sandbox", "install-external-provider", "--name", "youki"])
        .arg(&source)
        .output()
        .expect("kata sandbox install-external-provider runs");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(output.status.success(), "provisioning failed: {stdout}");
    let address = stdout
        .lines()
        .find_map(|line| line.strip_prefix("export KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS="))
        .expect("the provisioner prints the content address")
        .to_owned();
    let exports = vec![
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
    ];
    (exports, unseal)
}

/// One durable installed main, stopped with SIGTERM on drop.
struct Main {
    child: Child,
    url: String,
    log: PathBuf,
}

impl Main {
    fn start(root: &Path, config: &Path, delegated: bool, env: &[(String, String)]) -> Self {
        let log = root.join("serve.log");
        let log_file = std::fs::File::create(&log).unwrap();
        let mut command = if delegated {
            let mut command = Command::new("systemd-run");
            command.args(["--user", "--scope", "--quiet", "-p", "Delegate=yes", "--"]);
            command.arg(env!("CARGO_BIN_EXE_kata"));
            command
        } else {
            Command::new(env!("CARGO_BIN_EXE_kata"))
        };
        command
            .current_dir(repo_root())
            .env("KATA_STDLIB_DIR", repo_root().join("workflows/std"))
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
        // `systemd-run --scope` execs its command in place, so a delegated
        // child's pid is the main's own (measured: the pid a scoped
        // `sh -c 'echo $$'` printed was the spawned pid).
        let url = await_own_url(
            || match child.try_wait() {
                Ok(Some(status)) => ChildState::Ended(status.to_string()),
                Ok(None) | Err(_) => ChildState::Running { pid: child.id() },
            },
            config,
            &log,
        );
        Self { child, url, log }
    }

    /// Submit `pack` through the normal client path and wait for a terminal status;
    /// return `kata run show`'s document.
    fn run(&self, pack: &Path) -> serde_json::Value {
        let id = self.submit(pack);
        self.wait_terminal(&id)
    }

    /// Submit `pack` through the normal client path; return the execution id.
    fn submit(&self, pack: &Path) -> String {
        self.submit_with_params(pack, &[])
    }

    /// Submit `pack` with `kata run --param NAME=VALUE` for each of `params`;
    /// return the execution id.
    fn submit_with_params(&self, pack: &Path, params: &[(&str, &str)]) -> String {
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

    /// `kata run show <id>`'s document, once it reports a terminal status.
    fn wait_terminal(&self, id: &str) -> serde_json::Value {
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
                "execution {id} reached no terminal status; the main's log is {}",
                self.log.display()
            );
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    /// `kata run show <id>`'s document, if it parses.
    fn show(&self, id: &str) -> Option<serde_json::Value> {
        let shown = kata()
            .args(["--api-url", &self.url, "run", "show", id])
            .output()
            .expect("kata run show runs");
        serde_json::from_slice::<serde_json::Value>(&shown.stdout).ok()
    }

    /// The approval gate of execution `id` that `kata approvals` lists, waiting for one to
    /// appear — or `None` once the execution is terminal with none listed.
    fn next_gate(&self, id: &str) -> Option<serde_json::Value> {
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
            if self.show(id).is_some_and(|doc| {
                matches!(
                    doc["status"].as_str(),
                    Some("completed" | "failed" | "cancelled" | "timed_out")
                )
            }) {
                return None;
            }
            assert!(
                Instant::now() < deadline,
                "execution {id} listed no gate and reached no terminal status; the main's log \
                 is {}",
                self.log.display()
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// `kata run approve` / `kata run reject` one listed gate, through the client.
    fn decide(&self, gate: &serde_json::Value, reject: Option<&str>) {
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
}

impl Drop for Main {
    fn drop(&mut self) {
        // SIGTERM BY PID, the graceful path `kata serve` handles; then reap.
        let _ = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One CAS object's bytes, raw off `<data_dir>/cas.db` — an inline blob, the only shape a
/// manifest this small takes.
const CAS_OBJECT_SQL: &str =
    "SELECT blob FROM cas_objects WHERE object_id = ?1 AND storage = 'inline'";

fn raw_cas_object(data_dir: &Path, object: &[u8]) -> Vec<u8> {
    let conn = rusqlite::Connection::open_with_flags(
        data_dir.join("cas.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("a raw handle onto cas.db");
    conn.query_row(CAS_OBJECT_SQL, [object], |row| row.get(0))
        .expect("cas.db holds the result manifest inline")
}

/// `find /sys/fs/cgroup -type d -name <pattern>`, sorted — the kernel's answer.
fn cgroup_dirs(pattern: &str) -> Vec<String> {
    let output = Command::new("find")
        .args([
            "/sys/fs/cgroup",
            "-maxdepth",
            "12",
            "-type",
            "d",
            "-name",
            pattern,
        ])
        .stderr(Stdio::null())
        .output()
        .expect("find runs");
    let mut found: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_owned)
        .collect();
    found.sort();
    found
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Leg {
    /// An attempt directory left under `<worker state>/attempts`.
    AttemptRoot,
    /// The pinned youki's own `list` over a state root names a container, or could not
    /// answer.
    Runtime,
    /// The container's `kata.oci.<id>` cgroup directory.
    ContainerCgroup,
    /// A `kata.provider.*` cgroup directory that did not exist before the main started.
    ProviderCgroup,
    /// A live process placed in either cgroup.
    Process,
}

/// One piece of runtime state the host still holds.
#[derive(Debug)]
struct Residue {
    leg: Leg,
    detail: String,
}

/// Everything the OCI side's container runtime left on the HOST, read without kata.
/// `container` is the capsule's runtime id; `providers_before` the `kata.provider.*`
/// cgroup directories that existed before the oci main started (another run on the same
/// host may legitimately hold one, so the property is the DELTA).
///
/// The kill cell calls this WHILE its container runs and requires every leg but the
/// attempt root's to fire, so a leg that reads the wrong place cannot pass by seeing
/// nothing.
fn runtime_residue(
    worker_state: &Path,
    container: &str,
    providers_before: &[String],
) -> Vec<Residue> {
    let mut residue = Vec::new();
    let mut push = |leg, detail: String| residue.push(Residue { leg, detail });
    // 1. The attempt directories the worker keeps — each holds the provider's youki state
    //    root (`<attempt>/oci`), and a clean teardown or the next worker start's sweep
    //    removes it.
    let attempts = worker_state.join("attempts");
    if let Ok(entries) = std::fs::read_dir(&attempts) {
        for entry in entries.flatten() {
            push(Leg::AttemptRoot, entry.path().display().to_string());
        }
    }
    // 2. The RUNTIME's answer: `youki --root <r> list` over every state root under the
    //    worker's state directory — the provider's `<attempt>/oci/<container>/state`, one
    //    per container. A list that cannot answer is residue too: it proves nothing absent.
    let roots = Command::new("find")
        .arg(worker_state)
        .args(["-type", "d", "-path", "*/oci/*/state"])
        .stderr(Stdio::null())
        .output()
        .expect("find runs");
    for root in String::from_utf8_lossy(&roots.stdout).lines() {
        let listed = Command::new(kata_types::youki_pin::YoukiPin::embedded().store_path())
            .args(["--root", root, "list"])
            .output()
            .expect("the pinned youki lists");
        let listing = String::from_utf8_lossy(&listed.stdout);
        if !listed.status.success() {
            push(
                Leg::Runtime,
                format!(
                    "youki --root {root} list could not answer: {}",
                    String::from_utf8_lossy(&listed.stderr)
                ),
            );
        } else if listing.lines().skip(1).any(|line| !line.trim().is_empty()) {
            push(
                Leg::Runtime,
                format!("youki --root {root} list names a container:\n{listing}"),
            );
        }
    }
    // 3. The KERNEL's answer: the container's own cgroup, and any NEW provider subtree.
    let container_cgroup = format!("kata.oci.{container}");
    for dir in cgroup_dirs(&container_cgroup) {
        push(Leg::ContainerCgroup, dir);
    }
    let new_providers: Vec<String> = cgroup_dirs("kata.provider.*")
        .into_iter()
        .filter(|dir| !providers_before.contains(dir))
        .collect();
    for dir in &new_providers {
        push(Leg::ProviderCgroup, dir.clone());
    }
    // 4. The PROCESS TABLE's answer: no live process is placed in either.
    for entry in std::fs::read_dir("/proc").expect("/proc is readable") {
        let Ok(entry) = entry else { continue };
        let Ok(cgroups) = std::fs::read_to_string(entry.path().join("cgroup")) else {
            continue;
        };
        let stray = cgroups.lines().any(|line| {
            line.contains(&format!("/{container_cgroup}"))
                || new_providers
                    .iter()
                    .filter_map(|dir| Path::new(dir).file_name()?.to_str())
                    .any(|name| line.contains(&format!("/{name}")))
        });
        if stray {
            push(
                Leg::Process,
                format!(
                    "pid {} in {}",
                    entry.file_name().to_string_lossy(),
                    cgroups.trim()
                ),
            );
        }
    }
    residue
}

/// `residue` as one line per entry, for a failure message.
fn describe(residue: &[Residue]) -> String {
    residue
        .iter()
        .map(|r| format!("{:?}: {}", r.leg, r.detail))
        .collect::<Vec<_>>()
        .join("\n")
}

fn raw(data_dir: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        data_dir.join("operational.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("a second raw handle onto operational.db")
}

/// One durable installed main run as a transient systemd SERVICE — the production shape
/// `kata service install` writes (`KillMode=control-group`, a delegated cgroup) — rather
/// than a scope, because what a main's death does to its containers is the service
/// manager's answer, and a scope has none.
struct ServiceMain {
    unit: String,
    url: String,
}

impl ServiceMain {
    fn start(root: &Path, config: &Path, unit: &str, env: &[(String, String)]) -> Self {
        let log = root.join(format!("{unit}.log"));
        let mut command = Command::new("systemd-run");
        command
            .args(["--user", "--quiet", "--collect"])
            .arg(format!("--unit={unit}"))
            .args(["-p", "Delegate=yes", "-p", "KillMode=control-group"])
            .args(["-p", "RuntimeMaxSec=900"])
            .arg("-p")
            .arg(format!("WorkingDirectory={}", repo_root().display()))
            .arg("-p")
            .arg(format!("StandardOutput=append:{}", log.display()))
            .arg("-p")
            .arg(format!("StandardError=append:{}", log.display()));
        // A service does not inherit this process's environment: forward what a main
        // reads (its PATH, for `nix` and the provider's tools; every `KATA_*` knob).
        for (key, value) in std::env::vars()
            .filter(|(key, _)| key == "PATH" || key.starts_with("KATA_") || key.starts_with("NIX_"))
            .chain(env.iter().cloned())
        {
            command.arg(format!("--setenv={key}={value}"));
        }
        command
            .arg("--")
            .arg(env!("CARGO_BIN_EXE_kata"))
            .arg("serve")
            .arg("--config")
            .arg(config);
        let started = command.status().expect("systemd-run starts the service");
        assert!(started.success(), "systemd-run refused to start {unit}");
        // The service manager's MainPID is the main's own pid; 0 once the
        // unit's process is gone.
        let url = await_own_url(
            || match unit_main_pid(unit) {
                0 => ChildState::Ended(format!("{unit} has no main process")),
                pid => ChildState::Running { pid },
            },
            config,
            &log,
        );
        Self {
            unit: unit.to_owned(),
            url,
        }
    }

    /// The service's main pid, the service manager's answer.
    fn main_pid(&self) -> u32 {
        unit_main_pid(&self.unit)
    }
}

/// `unit`'s `MainPID`, the service manager's answer: 0 while it has none.
fn unit_main_pid(unit: &str) -> u32 {
    let output = Command::new("systemctl")
        .args(["--user", "show", "-p", "MainPID", "--value", unit])
        .output()
        .expect("systemctl show runs");
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .expect("a numeric MainPID")
}

/// The `[node] data_dir` `config` names: where the main it starts records
/// itself in `main.lock`.
fn config_data_dir(config: &Path) -> PathBuf {
    let text = std::fs::read_to_string(config).unwrap();
    let value: toml::Value = toml::from_str(&text).expect("the cell's config parses");
    value["node"]["data_dir"]
        .as_str()
        .map(PathBuf::from)
        .expect("the cell's config names [node] data_dir")
}

/// Wait until the main whose state `child` reports answers as itself — the
/// endpoint off its own `main.lock`, answering that lock's generation — and
/// return its URL; panic naming `log` if it ends or 120 s pass first.
fn await_own_url(child: impl FnMut() -> ChildState, config: &Path, log: &Path) -> String {
    await_own_main(&config_data_dir(config), child, Duration::from_secs(120)).unwrap_or_else(
        |error| {
            panic!(
                "{error}; its log is {}:\n{}",
                log.display(),
                std::fs::read_to_string(log).unwrap_or_default()
            )
        },
    )
}

impl Drop for ServiceMain {
    fn drop(&mut self) {
        let _ = Command::new("systemctl")
            .args(["--user", "stop", &self.unit])
            .status();
    }
}

/// `pgrep -f <pattern>`'s pids — the process table's answer.
fn pgrep(pattern: &str) -> Vec<String> {
    let output = Command::new("pgrep")
        .args(["-f", pattern])
        .output()
        .expect("pgrep runs");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Poll `check` every 500 ms until it answers `true`, or panic naming `what`.
fn wait_until(what: &str, within: Duration, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + within;
    while !check() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// The sleep only this cell's capsule runs, so `pgrep` finds its container and nothing
/// else on the host.
const KILL_CELL_SLEEP: &str = "sleep 293";

/// **A MAIN KILLED MID-CONTAINER TAKES ITS CONTAINER WITH IT, AND THE NEXT MAIN SETTLES THE
/// ATTEMPT.**
///
/// An `oci` main (supervising its node, as `kata init` configures it) runs as a transient
/// service in the shape `kata service install` writes, and a capsule that sleeps for
/// minutes is submitted through the client. Once the HOST sees the container's `sleep`,
/// the main is `SIGKILL`ed — no drop, no teardown, no stop. Then, read off the host and
/// never off kata:
///
/// * the service manager's `KillMode=control-group` takes the provider, the runtime and
///   the container with the main: `pgrep` finds no `sleep`, and the container's
///   `kata.oci.<id>` cgroup is gone;
/// * the NEXT main settles the attempt before any runner resumes — its last transition
///   `failed`, naming the restart and PROVEN AMBIGUOUS (read raw) — and the execution
///   reaches a terminal status through `kata run show`;
/// * with the next main up, and again after it stops, no runtime state survives: the
///   killed attempt's root (and the youki state in it) is reclaimed by the capsule
///   route's worker-start sweep, and no new `kata.provider.*` cgroup or stray process
///   remains ([`runtime_residue`]).
#[test]
#[ignore = "HOST-DEPENDENT like the differential (a certified rootless youki with its installed \
            AppArmor profile, a systemd user manager that delegates, the busybox closure \
            realised, `kata-provider-youki` built). Run alone, one test at a time: `cargo nextest \
            run -p kata -P live-smoke --test oci_main_live --run-ignored \
            all`."]
fn a_main_killed_mid_container_takes_the_container_with_it_and_the_next_main_settles_it_live() {
    assert!(
        pgrep(KILL_CELL_SLEEP).is_empty(),
        "the premise: nothing on this host already runs `{KILL_CELL_SLEEP}`"
    );
    let root = tempfile::tempdir().expect("an oci root");
    let config = write_config(root.path(), "oci");
    let (route, _unseal) = provision_provider(root.path());
    let data = root.path().join("data");
    let worker_state = data.join("oci-worker-state");
    let pack = root.path().join("kill-mid-container.star");
    std::fs::write(
        &pack,
        format!(
            "probe = stage(\n    id = \"probe\",\n    agent = \"shell\",\n    sandbox = \"iso\",\n    \
             prompt = \"{KILL_CELL_SLEEP}\",\n)\n\nworkflow(\n    \"kill-mid-container\",\n    \
             root = [probe],\n    sandbox_profiles = {{\"iso\": sandbox_profile(workspace = \
             \"rw\", net = \"offline\")}},\n)\n"
        ),
    )
    .unwrap();
    let providers_before = cgroup_dirs("kata.provider.*");
    let unit = format!("kata-kill-mid-container-{}", std::process::id());

    // -- THE FIRST MAIN: submit, see the container on the host, kill the main --------
    let first = ServiceMain::start(root.path(), &config, &format!("{unit}-a"), &route);
    let submitted = kata()
        .args(["--api-url", &first.url, "run"])
        .arg(&pack)
        .arg("--submit")
        .output()
        .expect("kata run --submit runs");
    let stdout = String::from_utf8_lossy(&submitted.stdout).into_owned();
    let id = stdout
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .and_then(|doc| doc["id"].as_str().map(str::to_owned))
        .unwrap_or_else(|| {
            panic!(
                "the submit printed no execution id: {stdout}{}",
                String::from_utf8_lossy(&submitted.stderr)
            )
        });
    wait_until(
        "the container's `sleep` to appear in the host's process table",
        Duration::from_secs(180),
        || !pgrep(KILL_CELL_SLEEP).is_empty(),
    );
    let capsule: Vec<u8> = raw(&data)
        .query_row("SELECT capsule_id FROM capsules", [], |row| row.get(0))
        .expect("exactly one capsule was authorized");
    let container = format!("kata-{}", hex::encode(capsule));
    // THE ORACLE, NON-VACUOUS: while the container runs, every leg that reads a running
    // container must see it — its attempt root, the runtime's list, its cgroup, a new
    // provider cgroup and a process placed in them. A leg reading the wrong place would
    // pass the later "nothing left" checks by seeing nothing here too.
    let live = runtime_residue(&worker_state, &container, &providers_before);
    for leg in [
        Leg::AttemptRoot,
        Leg::Runtime,
        Leg::ContainerCgroup,
        Leg::ProviderCgroup,
        Leg::Process,
    ] {
        assert!(
            live.iter().any(|residue| residue.leg == leg),
            "the premise: the oracle's {leg:?} leg sees the RUNNING container:\n{}",
            describe(&live)
        );
    }
    let killed = Command::new("kill")
        .args(["-KILL", &first.main_pid().to_string()])
        .status()
        .expect("kill runs");
    assert!(killed.success(), "the main was SIGKILLed");

    // -- THE HOST's answer: the service manager took the container with the main -----
    wait_until(
        "the container's `sleep` to leave the process table after the main's death",
        Duration::from_secs(60),
        || pgrep(KILL_CELL_SLEEP).is_empty(),
    );
    wait_until(
        "the container's cgroup to be removed after the main's death",
        Duration::from_secs(60),
        || cgroup_dirs(&format!("kata.oci.{container}")).is_empty(),
    );
    drop(first);

    // -- THE NEXT MAIN: settles the attempt before resume, the execution terminates --
    let second = ServiceMain::start(root.path(), &config, &format!("{unit}-b"), &route);
    let mut shown = serde_json::Value::Null;
    wait_until(
        "the killed execution to reach a terminal status on the next main",
        Duration::from_secs(180),
        || {
            let output = kata()
                .args(["--api-url", &second.url, "run", "show", &id])
                .output()
                .expect("kata run show runs");
            shown = serde_json::from_slice(&output.stdout).unwrap_or_default();
            matches!(
                shown["status"].as_str(),
                Some("completed" | "failed" | "cancelled" | "timed_out")
            )
        },
    );
    assert_eq!(shown["status"], "failed", "{shown}");
    let conn = raw(&data);
    let (attempts, state, reason): (i64, String, String) = conn
        .query_row(
            "SELECT (SELECT count(*) FROM attempts), t.resulting_state, \
                    coalesce(json_extract(t.payload_json, '$.reason'), '') \
               FROM transitions t JOIN attempts a ON a.attempt_id = t.attempt_id \
              WHERE a.occurrence_id IS NOT NULL ORDER BY t.seq DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("the capsule attempt's last transition");
    assert_eq!(state, "failed", "{reason}");
    assert!(
        reason.contains("the main restarted") && reason.contains("PROVEN AMBIGUOUS"),
        "the next main settled the attempt, ambiguously, naming the restart: {reason}"
    );
    assert_eq!(
        attempts, 1,
        "the settled capsule was not re-delivered as a second generation"
    );
    let residue = runtime_residue(&worker_state, &container, &providers_before);
    assert!(
        residue.is_empty(),
        "the killed attempt left runtime state behind with the next main up:\n{}",
        describe(&residue)
    );
    drop(second);
    let residue = runtime_residue(&worker_state, &container, &providers_before);
    assert!(
        residue.is_empty(),
        "runtime state survives the next main's stop:\n{}",
        describe(&residue)
    );
    println!(
        "KILL-MID-CONTAINER execution={id} container={container} attempts={attempts} \
         settled=\"{reason}\" runtime_residue=none"
    );
}

/// The sleep only the node double-fault cell's capsule runs.
const NODE_DOUBLE_FAULT_SLEEP: &str = "sleep 291";

/// `/proc/<pid>/stat`'s state letter, or `None` once the pid is gone.
fn process_state(pid: u32) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(") ")?.1.chars().next()
}

/// Whether `pid` still runs: present in the process table, neither a zombie nor dead.
fn running(pid: u32) -> bool {
    process_state(pid).is_some_and(|state| !matches!(state, 'Z' | 'X'))
}

/// The cgroup v2 directory `pid` is a member of, off `/proc/<pid>/cgroup`.
fn cgroup_of(pid: u32) -> PathBuf {
    let membership = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default();
    let relative = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .unwrap_or_else(|| panic!("pid {pid} has no cgroup v2 membership: {membership:?}"));
    Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/'))
}

/// Every pid placed anywhere in the cgroup subtree `dir`, off its `cgroup.procs` files.
fn members_of(dir: &Path) -> Vec<u32> {
    let mut members = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return members;
    };
    for entry in entries.flatten() {
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            members.extend(members_of(&entry.path()));
        }
    }
    let procs = std::fs::read_to_string(dir.join("cgroup.procs")).unwrap_or_default();
    members.extend(
        procs
            .lines()
            .filter_map(|pid| pid.trim().parse::<u32>().ok()),
    );
    members
}

/// The basename of the program `pid` runs: its `exe` link, else its command line's
/// first word (a process that is not dumpable answers `EACCES` for `exe`).
fn program_of(pid: u32) -> String {
    let path = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .or_else(|| {
            let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
            let first = cmdline.split(|byte| *byte == 0).next()?;
            Some(PathBuf::from(String::from_utf8_lossy(first).into_owned()))
        })
        .unwrap_or_default();
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The running children of `parent` that run `program`, off `/proc/<pid>/stat`.
fn children_running(parent: u32, program: &str) -> Vec<u32> {
    let mut children = Vec::new();
    for entry in std::fs::read_dir("/proc")
        .expect("/proc is readable")
        .flatten()
    {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse().ok())
        else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        // `stat`'s fourth field, the second after the command's closing parenthesis.
        let its_parent = stat
            .rsplit_once(") ")
            .and_then(|(_, rest)| rest.split_whitespace().nth(1))
            .and_then(|field| field.parse::<u32>().ok());
        if its_parent == Some(parent) && running(pid) && program_of(pid) == program {
            children.push(pid);
        }
    }
    children
}

/// What the main logs once it has dealt with a node that ended, before it pauses and
/// starts the next one (`supervised_node::supervise`).
const NODE_ENDED_LINE: &str = "supervised node ended;";

/// **A NODE KILLED WITH ITS PROVIDER MID-CONTAINER TAKES THE CONTAINER WITH IT BEFORE THE
/// MAIN MOVES ON.**
///
/// The double fault: a capsule's provider dies with its node, so neither the provider
/// (which kills its container when the node's frame stream closes) nor the node is left
/// to end the container. What ends it is the main: when its supervised node ends, it
/// kills the node's cgroup subtree (`cgroup.kill` on `<cgroup>/kata.node`) and waits for
/// it to empty before it reports the end, pauses, and starts the next node. An `oci` main
/// (supervising its node, as `kata init` configures it) runs in a delegated scope, and a
/// capsule that sleeps for minutes is submitted through the client. Once the HOST sees
/// the container's `sleep` in the node's subtree, every `kata-provider-youki` in that
/// subtree is stopped (`SIGSTOP`, so none reacts to the node's death), then the node and
/// those providers are `SIGKILL`ed. Then, read off the host and never off kata but for
/// the moment the main says it moved on:
///
/// * premises, while the container runs: the main took its delegated leaf
///   (`<cgroup>/kata.main`), its node is its one `kata-worker` child, in
///   `<cgroup>/kata.node`, and the container's `sleep` and at least one provider are
///   members of that subtree;
/// * when the main's log first reports the node's end, the container's `sleep` no longer
///   runs (gone from `/proc`, or a zombie), so the subtree was emptied before the pause,
///   not by the next node's start;
/// * the run fails, and the capsule attempt's raw last transition names the worker's
///   death and PROVEN AMBIGUOUS, the attempt never re-delivered;
/// * a new `kata-worker` child of the main runs, the main is alive throughout, and the
///   container's `kata.oci.<id>` cgroup is gone.
///
/// **Would red if:** the supervision loop did not empty the subtree after a node ended
/// (watched, with `supervise`'s `empty_node_subtree` after the node's exit deleted: the
/// container lived until the next node's start emptied the stale subtree, a pause later).
#[test]
#[ignore = "HOST-DEPENDENT like the differential (a certified rootless youki with its installed \
            AppArmor profile, a delegated user scope, the busybox closure realised, \
            `kata-provider-youki` built). Run alone, one test at a time: `cargo nextest run -p \
            kata -P live-smoke --test oci_main_live --run-ignored all`."]
fn a_node_killed_with_its_provider_takes_its_container_before_the_main_moves_on_live() {
    assert!(
        pgrep(NODE_DOUBLE_FAULT_SLEEP).is_empty(),
        "the premise: nothing on this host already runs `{NODE_DOUBLE_FAULT_SLEEP}`"
    );
    let root = tempfile::tempdir().expect("an oci root");
    let config = write_config(root.path(), "oci");
    let (route, _unseal) = provision_provider(root.path());
    let data = root.path().join("data");
    let pack = root.path().join("node-double-fault.star");
    std::fs::write(
        &pack,
        format!(
            "probe = stage(\n    id = \"probe\",\n    agent = \"shell\",\n    sandbox = \"iso\",\n    \
             timeout_ms = 600000,\n    prompt = \"{NODE_DOUBLE_FAULT_SLEEP}\",\n)\n\nworkflow(\n    \
             \"node-double-fault\",\n    root = [probe],\n    sandbox_profiles = {{\"iso\": \
             sandbox_profile(workspace = \"rw\", net = \"offline\")}},\n)\n"
        ),
    )
    .unwrap();

    let main = Main::start(root.path(), &config, true, &route);
    let main_pid = main.child.id();
    let main_cgroup = cgroup_of(main_pid);
    assert!(
        main_cgroup.ends_with("kata.main"),
        "the premise: the main moved itself into its delegated cgroup's `kata.main`: {}",
        main_cgroup.display()
    );
    let node_subtree = main_cgroup
        .parent()
        .expect("kata.main has a parent")
        .join("kata.node");
    let submitted = kata()
        .args(["--api-url", &main.url, "run"])
        .arg(&pack)
        .arg("--submit")
        .output()
        .expect("kata run --submit runs");
    let stdout = String::from_utf8_lossy(&submitted.stdout).into_owned();
    let id = stdout
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .and_then(|doc| doc["id"].as_str().map(str::to_owned))
        .unwrap_or_else(|| {
            panic!(
                "the submit printed no execution id: {stdout}{}",
                String::from_utf8_lossy(&submitted.stderr)
            )
        });
    wait_until(
        "the container's `sleep` to appear in the host's process table",
        Duration::from_secs(180),
        || !pgrep(NODE_DOUBLE_FAULT_SLEEP).is_empty(),
    );
    let capsule: Vec<u8> = raw(&data)
        .query_row("SELECT capsule_id FROM capsules", [], |row| row.get(0))
        .expect("exactly one capsule was authorized");
    let container = format!("kata-{}", hex::encode(capsule));
    let sleeps: Vec<u32> = pgrep(NODE_DOUBLE_FAULT_SLEEP)
        .iter()
        .filter_map(|pid| pid.parse().ok())
        .collect();
    for sleep in &sleeps {
        assert!(
            cgroup_of(*sleep).starts_with(&node_subtree),
            "the premise: the container's process {sleep} is in the node's subtree {}: {}",
            node_subtree.display(),
            cgroup_of(*sleep).display()
        );
    }
    let nodes = children_running(main_pid, "kata-worker");
    assert_eq!(
        nodes.len(),
        1,
        "the premise: the main supervises one node: {nodes:?}"
    );
    let node = nodes[0];
    assert!(
        cgroup_of(node).starts_with(&node_subtree),
        "the premise: the node runs in {}: {}",
        node_subtree.display(),
        cgroup_of(node).display()
    );
    let providers: Vec<u32> = members_of(&node_subtree)
        .into_iter()
        .filter(|pid| program_of(*pid) == "kata-provider-youki")
        .collect();
    assert!(
        !providers.is_empty(),
        "the premise: the container's provider runs in the node's subtree {}: members {:?}",
        node_subtree.display(),
        members_of(&node_subtree)
    );
    let log_before = std::fs::read_to_string(&main.log).unwrap_or_default();
    assert!(
        !log_before.contains(NODE_ENDED_LINE),
        "the premise: no node ended before the fault:\n{log_before}"
    );

    // -- THE DOUBLE FAULT: the providers cannot act, then they die with the node ------
    let pids: Vec<String> = providers.iter().map(u32::to_string).collect();
    let stopped = Command::new("kill")
        .arg("-STOP")
        .args(&pids)
        .status()
        .expect("kill runs");
    assert!(stopped.success(), "the providers {pids:?} were stopped");
    let killed = Command::new("kill")
        .arg("-KILL")
        .arg(node.to_string())
        .args(&pids)
        .status()
        .expect("kill runs");
    assert!(
        killed.success(),
        "the node {node} and its providers were SIGKILLed"
    );

    // -- THE ORDER: the container is gone by the time the main moves on ---------------
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let log = std::fs::read_to_string(&main.log).unwrap_or_default();
        if log.contains(NODE_ENDED_LINE) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the main never reported its node's end; its log is {}:\n{log}",
            main.log.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let outliving: Vec<u32> = sleeps.iter().copied().filter(|pid| running(*pid)).collect();
    assert!(
        outliving.is_empty(),
        "the container's processes {outliving:?} still ran when the main reported its node's \
         end: the dead node's subtree {} was not emptied before the main moved on",
        node_subtree.display()
    );

    // -- THE SETTLEMENT and the next node ----------------------------------------------
    let shown = main.wait_terminal(&id);
    assert_eq!(shown["status"], "failed", "{shown}");
    let (attempts, state, reason): (i64, String, String) = raw(&data)
        .query_row(
            "SELECT (SELECT count(*) FROM attempts WHERE stage_id = 'probe'), \
                    t.resulting_state, coalesce(json_extract(t.payload_json, '$.reason'), '') \
               FROM transitions t JOIN attempts a ON a.attempt_id = t.attempt_id \
              WHERE a.stage_id = 'probe' ORDER BY t.seq DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("the capsule attempt's last transition");
    assert_eq!(state, "failed", "{reason}");
    assert!(
        reason.contains("died") && reason.contains("PROVEN AMBIGUOUS"),
        "the main settled the attempt, ambiguously, naming the worker's death: {reason}"
    );
    assert_eq!(attempts, 1, "the settled capsule was not re-delivered");
    let mut next = Vec::new();
    wait_until(
        "a new node to run as the main's child",
        Duration::from_secs(60),
        || {
            next = children_running(main_pid, "kata-worker");
            next.len() == 1 && next[0] != node
        },
    );
    assert!(
        running(main_pid),
        "the main is alive after its node's death"
    );
    assert!(
        cgroup_dirs(&format!("kata.oci.{container}")).is_empty(),
        "the container's cgroup is gone"
    );
    println!(
        "NODE-DOUBLE-FAULT execution={id} container={container} node={node} \
         providers={providers:?} next_node={next:?} settled=\"{reason}\""
    );
}

/// The sleep only the stalled-node cell's capsule runs.
const NODE_STALL_SLEEP: &str = "sleep 295";

/// Whether `state` is an attempt's terminal `resulting_state`.
fn terminal_attempt_state(state: &str) -> bool {
    matches!(state, "completed" | "failed" | "cancelled" | "orphaned")
}

/// The last raw transition of the capsule attempt of `stage`, with the stage's attempt
/// count: `(attempts, resulting_state, reason)`.
fn last_attempt_transition(data: &Path, stage: &str) -> Option<(i64, String, String)> {
    raw(data)
        .query_row(
            "SELECT (SELECT count(*) FROM attempts WHERE stage_id = ?1), \
                    t.resulting_state, coalesce(json_extract(t.payload_json, '$.reason'), '') \
               FROM transitions t JOIN attempts a ON a.attempt_id = t.attempt_id \
              WHERE a.stage_id = ?1 ORDER BY t.seq DESC LIMIT 1",
            [stage],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .ok()
}

/// **A STOPPED NODE IS KILLED, WITH ITS CONTAINER, BEFORE ITS ATTEMPT SETTLES, AND A
/// NEW NODE TAKES THE WORK.**
///
/// A node that stops answering without ending keeps its connection open: its heartbeat
/// deadline is the only thing that notices it. When the main's heartbeat sweep judges
/// its supervised node dead, the main kills that node's cgroup subtree
/// (`cgroup.kill` on `<cgroup>/kata.node`) and reaps it before it settles anything the
/// node held, so the node never resumes on its old connection and none of its
/// containers outlives the verdict; the supervision then starts a new node, which
/// enrolls afresh. The cell sees the node reaped and the container gone by the first
/// read of the settlement, not which kill took the container: the fence's, or the
/// supervision's emptying of the subtree just after the fence answered. An `oci` main (supervising its node, `heartbeat_interval_ms = 1000`,
/// `heartbeat_grace_ms = 5000`) runs in a delegated scope, and a capsule that sleeps for
/// minutes is submitted through the client. Once the HOST sees the container's `sleep`
/// in the node's subtree, the node alone is stopped (`SIGSTOP`). Then, read off the host
/// and the raw ledger:
///
/// * premises, while the container runs: the main took its delegated leaf, its node is
///   its one `kata-worker` child, in `<cgroup>/kata.node`, and the container's `sleep`
///   is a member of that subtree;
/// * at the first raw read of the attempt's settlement, the stopped node is gone from
///   the process table and the container's `sleep` no longer runs;
/// * that settlement is the heartbeat leg's: `failed`, PROVEN AMBIGUOUS, its reason
///   naming the observed silence, the node's process in state `T` (the evidence the
///   verdict was taken on) and the kill of that process, never the closed connection;
///   the attempt was not re-delivered (attempts=1) and the run fails;
/// * a new `kata-worker` child of the main runs in `<cgroup>/kata.node`, and it takes
///   work: a shell stage submitted next (retried only while refused for want of a live
///   worker, until the new node enrolls) completes, its raw attempt placed on a worker
///   id the stopped node never had; the main is alive throughout and the container's
///   `kata.oci.<id>` cgroup is gone.
///
/// **Would red if:** the heartbeat leg settled a dead node's attempts without killing
/// it (watched, with `handle_worker_death`'s fence of a heartbeat-dead worker removed:
/// the attempt settled while the node was still in the process table, stopped), or
/// killed it without holding `worker_deaths` across the kill and the settlement
/// (watched, with that lock removed: the killed node's reactor settled the attempt first,
/// naming only its closed connection and the node's process in state `Z`).
#[test]
#[ignore = "HOST-DEPENDENT like the differential (a certified rootless youki with its installed \
            AppArmor profile, a delegated user scope, the busybox closure realised, \
            `kata-provider-youki` built). Run alone, one test at a time: `cargo nextest run -p \
            kata -P live-smoke --test oci_main_live --run-ignored all`."]
fn a_stopped_node_is_killed_with_its_container_before_its_attempt_settles_live() {
    assert!(
        pgrep(NODE_STALL_SLEEP).is_empty(),
        "the premise: nothing on this host already runs `{NODE_STALL_SLEEP}`"
    );
    let root = tempfile::tempdir().expect("an oci root");
    let config = write_config(root.path(), "oci");
    let (route, _unseal) = provision_provider(root.path());
    let data = root.path().join("data");
    let stall = root.path().join("node-stall.star");
    std::fs::write(
        &stall,
        format!(
            "probe = stage(\n    id = \"probe\",\n    agent = \"shell\",\n    sandbox = \"iso\",\n    \
             timeout_ms = 600000,\n    prompt = \"{NODE_STALL_SLEEP}\",\n)\n\nworkflow(\n    \
             \"node-stall\",\n    root = [probe],\n    sandbox_profiles = {{\"iso\": \
             sandbox_profile(workspace = \"rw\", net = \"offline\")}},\n)\n"
        ),
    )
    .unwrap();
    let after = root.path().join("after-stall.star");
    std::fs::write(
        &after,
        "after = stage(\n    id = \"after\",\n    agent = \"shell\",\n    sandbox = \"iso\",\n    \
         prompt = \"echo the new node took work\",\n)\n\nworkflow(\n    \"after-stall\",\n    \
         root = [after],\n    sandbox_profiles = {\"iso\": sandbox_profile(workspace = \"rw\", \
         net = \"offline\")},\n)\n",
    )
    .unwrap();

    let main = Main::start(root.path(), &config, true, &route);
    let main_pid = main.child.id();
    let main_cgroup = cgroup_of(main_pid);
    assert!(
        main_cgroup.ends_with("kata.main"),
        "the premise: the main moved itself into its delegated cgroup's `kata.main`: {}",
        main_cgroup.display()
    );
    let node_subtree = main_cgroup
        .parent()
        .expect("kata.main has a parent")
        .join("kata.node");
    let id = main.submit(&stall);
    wait_until(
        "the container's `sleep` to appear in the host's process table",
        Duration::from_secs(180),
        || !pgrep(NODE_STALL_SLEEP).is_empty(),
    );
    let capsule: Vec<u8> = raw(&data)
        .query_row("SELECT capsule_id FROM capsules", [], |row| row.get(0))
        .expect("exactly one capsule was authorized");
    let container = format!("kata-{}", hex::encode(capsule));
    let sleeps: Vec<u32> = pgrep(NODE_STALL_SLEEP)
        .iter()
        .filter_map(|pid| pid.parse().ok())
        .collect();
    for sleep in &sleeps {
        assert!(
            cgroup_of(*sleep).starts_with(&node_subtree),
            "the premise: the container's process {sleep} is in the node's subtree {}: {}",
            node_subtree.display(),
            cgroup_of(*sleep).display()
        );
    }
    let nodes = children_running(main_pid, "kata-worker");
    assert_eq!(
        nodes.len(),
        1,
        "the premise: the main supervises one node: {nodes:?}"
    );
    let node = nodes[0];
    assert!(
        cgroup_of(node).starts_with(&node_subtree),
        "the premise: the node runs in {}: {}",
        node_subtree.display(),
        cgroup_of(node).display()
    );
    let worker: String = raw(&data)
        .query_row(
            "SELECT worker_id FROM attempts WHERE stage_id = 'probe'",
            [],
            |row| row.get(0),
        )
        .expect("the capsule attempt is placed on the node");
    let before = last_attempt_transition(&data, "probe");
    assert!(
        before
            .as_ref()
            .is_some_and(|(_, state, _)| !terminal_attempt_state(state)),
        "the premise: the capsule attempt is unsettled before the node stops: {before:?}"
    );

    // -- THE STALL: the node stops answering, its connection open ------------------------
    let stopped = Command::new("kill")
        .arg("-STOP")
        .arg(node.to_string())
        .status()
        .expect("kill runs");
    assert!(stopped.success(), "the node {node} was stopped");
    let stopped_at = Instant::now();

    // -- THE ORDER: the node and its container are gone when the attempt settles --------
    let (attempts, state, reason) = loop {
        if let Some(settled) = last_attempt_transition(&data, "probe")
            .filter(|(_, state, _)| terminal_attempt_state(state))
        {
            break settled;
        }
        assert!(
            stopped_at.elapsed() < Duration::from_secs(60),
            "the stopped node's attempt never settled; the main's log is {}",
            main.log.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let node_at_settlement = process_state(node);
    let outliving: Vec<u32> = sleeps.iter().copied().filter(|pid| running(*pid)).collect();
    let settled_after = stopped_at.elapsed();
    assert!(
        node_at_settlement.is_none(),
        "the stopped node {node} was still in the process table (state {node_at_settlement:?}) \
         when its attempt settled: {reason}"
    );
    assert!(
        outliving.is_empty(),
        "the container's processes {outliving:?} still ran when the stopped node's attempt \
         settled: {reason}"
    );
    assert_eq!(state, "failed", "{reason}");
    assert!(
        reason.contains("no heartbeat")
            && reason.contains(&format!("its process {node} exists in state T"))
            && reason.contains(&format!("the main killed its node, process {node}"))
            && reason.contains("PROVEN AMBIGUOUS")
            && !reason.contains("connection closed"),
        "the heartbeat leg settled the attempt, ambiguously, naming the stopped process and \
         its kill: {reason}"
    );
    assert_eq!(attempts, 1, "the settled capsule was not re-delivered");
    let shown = main.wait_terminal(&id);
    assert_eq!(shown["status"], "failed", "{shown}");

    // -- THE NEXT NODE enrolls and takes work -------------------------------------------
    let mut next = Vec::new();
    wait_until(
        "a new node to run as the main's child",
        Duration::from_secs(60),
        || {
            next = children_running(main_pid, "kata-worker");
            next.len() == 1 && next[0] != node
        },
    );
    assert!(
        cgroup_of(next[0]).starts_with(&node_subtree),
        "the new node runs in {}: {}",
        node_subtree.display(),
        cgroup_of(next[0]).display()
    );
    // Readiness is not re-published for a new node: until it enrolls, a submit is
    // refused for want of a live worker, and only that refusal is retried.
    let deadline = Instant::now() + Duration::from_secs(120);
    let after_id = loop {
        let submitted = kata()
            .args(["--api-url", &main.url, "run"])
            .arg(&after)
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
            break id;
        }
        let stderr = String::from_utf8_lossy(&submitted.stderr);
        assert!(
            stderr.contains("no worker is currently available") && Instant::now() < deadline,
            "the submit after the stopped node's kill was not accepted: {stdout}{stderr}; the \
             main's log is {}",
            main.log.display()
        );
        std::thread::sleep(Duration::from_secs(1));
    };
    let took = main.wait_terminal(&after_id);
    assert_eq!(took["status"], "completed", "{took}");
    let (after_worker, after_state): (String, String) = raw(&data)
        .query_row(
            "SELECT a.worker_id, t.resulting_state \
               FROM transitions t JOIN attempts a ON a.attempt_id = t.attempt_id \
              WHERE a.stage_id = 'after' ORDER BY t.seq DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the next stage's attempt");
    assert_eq!(after_state, "completed");
    assert_ne!(
        after_worker, worker,
        "the next stage ran on a newly enrolled worker, not the stopped node's"
    );
    assert!(
        process_state(node).is_none(),
        "the stopped node {node} never came back"
    );
    assert!(
        running(main_pid),
        "the main is alive after its node's death"
    );
    assert!(
        cgroup_dirs(&format!("kata.oci.{container}")).is_empty(),
        "the container's cgroup is gone"
    );
    println!(
        "NODE-STALL execution={id} container={container} node={node} worker={worker} \
         next_node={next:?} next_worker={after_worker} settled_after_ms={} settled=\"{reason}\"",
        settled_after.as_millis()
    );
}

/// The sleep only the main-stall cell's capsule runs.
const MAIN_STALL_SLEEP: &str = "sleep 289";

/// **A MAIN STOPPED SEVEN SECONDS KEEPS ITS SUPERVISED NODE AND THE NODE'S CONTAINER.**
///
/// A dead verdict on the supervised node kills it with its subtree, so a false one costs
/// the node's containers. A stall of the main itself must not produce one: the heartbeat
/// sweep charges a worker at most one interval of the main's own stall
/// (`HeartbeatMonitor::sweep`). An `oci` main (supervising its node,
/// `heartbeat_interval_ms = 1000`, `heartbeat_grace_ms = 5000`) runs in a delegated scope,
/// and a capsule that sleeps for minutes is submitted through the client. Once the HOST
/// sees the container's `sleep` in the node's subtree, the MAIN is stopped (`SIGSTOP`) for
/// 7 s, past the node's 6 s deadline, then resumed and given 12 s more of sweeps. Read off
/// the host and the raw ledger:
///
/// * the node is the same process, still running, and the main's only `kata-worker` child;
/// * every process of the container's `sleep` still runs;
/// * the capsule attempt is unsettled on the node's worker id, attempts=1;
///
/// and once the main is stopped gracefully, the container's `sleep` is gone with it.
///
/// **Would red if:** the sweep charged the main's own stall to its workers (watched, with
/// `HeartbeatMonitor::sweep`'s one-interval cap removed: the node was judged dead and
/// killed with its container).
#[test]
#[ignore = "HOST-DEPENDENT like the differential (a certified rootless youki with its installed \
            AppArmor profile, a delegated user scope, the busybox closure realised, \
            `kata-provider-youki` built). Run alone, one test at a time: `cargo nextest run -p \
            kata -P live-smoke --test oci_main_live --run-ignored all`."]
fn a_main_stopped_seven_seconds_keeps_its_supervised_node_and_its_container_live() {
    assert!(
        pgrep(MAIN_STALL_SLEEP).is_empty(),
        "the premise: nothing on this host already runs `{MAIN_STALL_SLEEP}`"
    );
    let root = tempfile::tempdir().expect("an oci root");
    let config = write_config(root.path(), "oci");
    let (route, _unseal) = provision_provider(root.path());
    let data = root.path().join("data");
    let pack = root.path().join("main-stall.star");
    std::fs::write(
        &pack,
        format!(
            "probe = stage(\n    id = \"probe\",\n    agent = \"shell\",\n    sandbox = \"iso\",\n    \
             timeout_ms = 600000,\n    prompt = \"{MAIN_STALL_SLEEP}\",\n)\n\nworkflow(\n    \
             \"main-stall\",\n    root = [probe],\n    sandbox_profiles = {{\"iso\": \
             sandbox_profile(workspace = \"rw\", net = \"offline\")}},\n)\n"
        ),
    )
    .unwrap();

    let main = Main::start(root.path(), &config, true, &route);
    let main_pid = main.child.id();
    let main_cgroup = cgroup_of(main_pid);
    assert!(
        main_cgroup.ends_with("kata.main"),
        "the premise: the main moved itself into its delegated cgroup's `kata.main`: {}",
        main_cgroup.display()
    );
    let node_subtree = main_cgroup
        .parent()
        .expect("kata.main has a parent")
        .join("kata.node");
    let id = main.submit(&pack);
    wait_until(
        "the container's `sleep` to appear in the host's process table",
        Duration::from_secs(180),
        || !pgrep(MAIN_STALL_SLEEP).is_empty(),
    );
    let sleeps: Vec<u32> = pgrep(MAIN_STALL_SLEEP)
        .iter()
        .filter_map(|pid| pid.parse().ok())
        .collect();
    for sleep in &sleeps {
        assert!(
            cgroup_of(*sleep).starts_with(&node_subtree),
            "the premise: the container's process {sleep} is in the node's subtree {}: {}",
            node_subtree.display(),
            cgroup_of(*sleep).display()
        );
    }
    let nodes = children_running(main_pid, "kata-worker");
    assert_eq!(
        nodes.len(),
        1,
        "the premise: the main supervises one node: {nodes:?}"
    );
    let node = nodes[0];
    let worker: String = raw(&data)
        .query_row(
            "SELECT worker_id FROM attempts WHERE stage_id = 'probe'",
            [],
            |row| row.get(0),
        )
        .expect("the capsule attempt is placed on the node");

    // -- THE STALL: the main stops, past the node's deadline, and resumes ---------------
    let signal = |name: &str| {
        let sent = Command::new("kill")
            .arg(format!("-{name}"))
            .arg(main_pid.to_string())
            .status()
            .expect("kill runs");
        assert!(sent.success(), "SIG{name} reached the main {main_pid}");
    };
    signal("STOP");
    let stopped_at = Instant::now();
    std::thread::sleep(Duration::from_secs(7));
    signal("CONT");
    let stopped_for = stopped_at.elapsed();
    std::thread::sleep(Duration::from_secs(12));

    // -- THE NODE, ITS CONTAINER AND ITS ATTEMPT are as they were -----------------------
    let nodes_now = children_running(main_pid, "kata-worker");
    let outlived: Vec<u32> = sleeps.iter().copied().filter(|pid| running(*pid)).collect();
    let now = last_attempt_transition(&data, "probe");
    assert!(
        running(node) && nodes_now == [node],
        "the node {node} was replaced after the main stopped {stopped_for:?}: it reads \
         {:?}, the main's nodes now {nodes_now:?}, the attempt {now:?}; the main's log is {}",
        process_state(node),
        main.log.display()
    );
    assert_eq!(
        outlived, sleeps,
        "the container's processes {sleeps:?} did not all outlive the main's {stopped_for:?} \
         stop: {now:?}"
    );
    let (attempts, state, reason) = now.expect("the capsule attempt has transitions");
    assert!(
        !terminal_attempt_state(&state),
        "the capsule attempt settled after the main's {stopped_for:?} stop: {state} {reason}"
    );
    assert_eq!(attempts, 1, "the capsule attempt was not re-delivered");
    let placed: String = raw(&data)
        .query_row(
            "SELECT worker_id FROM attempts WHERE stage_id = 'probe'",
            [],
            |row| row.get(0),
        )
        .expect("the capsule attempt is still placed");
    assert_eq!(placed, worker, "the attempt stays on the node's worker id");

    drop(main);
    wait_until(
        "the container's `sleep` to end with the main's graceful stop",
        Duration::from_secs(60),
        || pgrep(MAIN_STALL_SLEEP).is_empty(),
    );
    println!(
        "MAIN-STALL execution={id} main={main_pid} stopped_for_ms={} node={node} \
         worker={worker} sleeps={sleeps:?} attempt_state={state}",
        stopped_for.as_millis()
    );
}

/// **A CAPSULE THAT RUNS PAST 120 SECONDS COMPLETES ON ITS OWN WALL CLOCK.**
///
/// A stage's hashed `timeout_ms` is the only wall clock. A provider supervisor that
/// held every assignment to a constant 120 s would SIGKILL a capsule that asked for
/// three minutes at two (`provider_crash_contained ... produced no frame within 120s`).
/// Here one shell stage declares `timeout_ms = 180000` and sleeps 130 s on a durable
/// `oci` main, submitted through the client: the execution completes, its occurrence
/// is accepted (read raw), and the capsule's wall clock — not a constant — is what the
/// provider was held to.
#[test]
#[ignore = "HOST-DEPENDENT like the differential (a certified rootless youki with its installed \
            AppArmor profile, a delegated user scope, the busybox closure realised, \
            `kata-provider-youki` built), and SLOW (a 130 s container). Run alone, one test at \
            a time: `cargo nextest run -p kata -P live-smoke --test \
            oci_main_live --run-ignored all`."]
fn a_capsule_past_120_seconds_completes_on_its_own_wall_clock_live() {
    let root = tempfile::tempdir().expect("an oci root");
    let config = write_config(root.path(), "oci");
    let (route, _unseal) = provision_provider(root.path());
    let pack = root.path().join("long-capsule.star");
    std::fs::write(
        &pack,
        "probe = stage(\n    id = \"probe\",\n    agent = \"shell\",\n    sandbox = \"iso\",\n    \
         timeout_ms = 180000,\n    prompt = \"sleep 130; echo slept\",\n)\n\nworkflow(\n    \
         \"long-capsule\",\n    root = [probe],\n    sandbox_profiles = {\"iso\": \
         sandbox_profile(workspace = \"rw\", net = \"offline\")},\n)\n",
    )
    .unwrap();
    let started = Instant::now();
    let doc = {
        let main = Main::start(root.path(), &config, true, &route);
        main.run(&pack)
    };
    let elapsed = started.elapsed();
    assert_eq!(doc["status"], "completed", "{doc}");
    assert!(
        elapsed >= Duration::from_secs(130),
        "the stage really ran past 120 s ({elapsed:?})"
    );
    let conn = raw(&root.path().join("data"));
    let (accepted, state): (Option<Vec<u8>>, String) = conn
        .query_row(
            "SELECT o.accepted_attempt_id, \
                    (SELECT t.resulting_state FROM transitions t \
                      WHERE t.attempt_id = o.accepted_attempt_id ORDER BY t.seq DESC LIMIT 1) \
               FROM occurrences o",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("exactly one occurrence");
    assert!(accepted.is_some(), "the occurrence is accepted");
    assert_eq!(state, "completed");
    println!(
        "LONG-CAPSULE execution={} elapsed={elapsed:?} accepted=yes",
        doc["id"]
    );
}

/// THE `/work` APPLY AS A MAIN-OWNED EFFECT, live: `first`
/// writes `hello.txt` into the container's bound `/work`, the main's apply
/// commits the recorded delta onto the execution's jj candidate, and `second`'s
/// container reads the file out of the APPLIED head — a write that only a real
/// main-side apply could have made visible.
///
/// Asserted from OUTSIDE kata's own readers: the run's terminal document, the
/// raw head row (`head_seq` advanced, a NEW candidate commit id), the apply
/// attempt's `#apply/first` coordinates, and `git show <candidate>:hello.txt`
/// — the jj apply's commit, read by git, never by kata.
const WORK_APPLY_PACK: &str = "
first = stage(
    id = \"first\",
    agent = \"shell\",
    sandbox = \"iso\",
    produces_files = [\"hello.txt\"],
    prompt = \"\"\"printf 'from-first\\n' > /work/hello.txt
printf '{\"wrote\": true}\\n'
\"\"\",
    outputs = { \"wrote\": \"bool\" },
)
second = stage(
    id = \"second\",
    agent = \"shell\",
    sandbox = \"iso\",
    depends_on = [first],
    prompt = \"\"\"printf '{\"content\": \"%s\"}\\n' \"$(cat /work/hello.txt)\"
\"\"\",
    outputs = { \"content\": \"string\" },
)
workflow(
    \"work-apply-two-stage\",
    root = [first, second],
    worktree_isolated = True,
    sandbox_profiles = {
        \"iso\": sandbox_profile(
            workspace = \"rw\",
            net = \"offline\",
        ),
    },
)
";

#[test]
#[ignore = "HOST-DEPENDENT like the differential (a certified rootless youki with its installed \
            AppArmor profile, a delegated user scope, the busybox closure realised, \
            `kata-provider-youki` built). Run alone, one test at a time: `cargo nextest run -p \
            kata -P live-smoke --test oci_main_live --run-ignored all`."]
fn a_two_stage_oci_run_applies_the_first_stages_work_delta_before_the_second_live() {
    // The fixture repository `[vcs] jj_repo` answers — a plain committed repo
    // with one marker file; the apply's candidate must land on ITS trunk's
    // object store.
    let fixture = tempfile::tempdir().expect("a fixture root");
    let repo = fixture.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    kata_test_utils::git::init_git_repo_at(&repo);
    let root = tempfile::tempdir().expect("an oci root");
    let config = write_config(root.path(), "oci");
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        format!(
            "{text}\n[vcs]\njj_repo = \"{}\"\ntrunk = \"main\"\n",
            repo.display()
        ),
    )
    .unwrap();
    let (route, _unseal) = provision_provider(root.path());
    let data = root.path().join("data");
    let pack = root.path().join("work-apply-two-stage.star");
    std::fs::write(&pack, WORK_APPLY_PACK).unwrap();
    let worker_state = data.join("oci-worker-state");
    let providers_before = cgroup_dirs("kata.provider.*");
    let (doc, containers) = {
        let main = Main::start(root.path(), &config, true, &route);
        let doc = main.run(&pack);
        let containers: Vec<String> = {
            let conn = raw(&data);
            let mut statement = conn.prepare("SELECT capsule_id FROM capsules").unwrap();
            statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .unwrap()
                .map(|capsule| format!("kata-{}", hex::encode(capsule.unwrap())))
                .collect()
        };
        for container in &containers {
            let residue = runtime_residue(&worker_state, container, &providers_before);
            assert!(
                residue.is_empty(),
                "capsule {container} left runtime state behind while its main is up:
{}",
                describe(&residue)
            );
        }
        (doc, containers)
    };
    for container in &containers {
        let residue = runtime_residue(&worker_state, container, &providers_before);
        assert!(
            residue.is_empty(),
            "the stopped oci main left runtime state behind for {container}:
{}",
            describe(&residue)
        );
    }
    assert_eq!(doc["status"], "completed", "oci: {doc}");
    // THE USER-VISIBLE PROOF: `second` read `hello.txt` out of its `/work` — a
    // file only `first`'s applied delta could have placed in the head it was
    // materialized from.
    assert_eq!(
        doc["outputs"]["second"]["parsed"]["content"], "from-first",
        "the second stage saw the first's write: {doc}"
    );
    assert_eq!(
        doc["outputs"]["first"]["parsed"]["wrote"], true,
        "the first stage ran: {doc}"
    );

    // THE DURABLE RECORD, raw: the apply ran at `#apply/first` as a
    // main-executor attempt, and the head advanced onto a NEW candidate commit.
    let conn = raw(&data);
    let apply_attempts: i64 = conn
        .query_row(
            "SELECT count(*) FROM attempts WHERE stage_id = '#apply/first'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(apply_attempts, 1, "one WorkApply attempt for `first`");
    let (base_commit, candidate_commit, head_seq): (String, String, i64) = conn
        .query_row(
            "SELECT base_commit, candidate_commit_id, head_seq FROM execution_work_tree_heads",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("the execution's head row");
    assert_eq!(head_seq, 1, "exactly one apply advanced the head");
    assert_ne!(
        candidate_commit, base_commit,
        "the head moved onto the applied candidate"
    );

    // THE COMMIT ITSELF, read by GIT — the apply's jj write, observed without
    // kata's eyes.
    let shown = hermetic_git_in(&repo)
        .args(["show", &format!("{candidate_commit}:hello.txt")])
        .output()
        .expect("git show runs");
    if !shown.status.success() {
        let tree = hermetic_git_in(&repo)
            .args(["ls-tree", "-r", "--name-only", &candidate_commit])
            .output()
            .expect("git ls-tree runs");
        panic!(
            "the applied commit is readable: {}\nls-tree:\n{}",
            String::from_utf8_lossy(&shown.stderr),
            String::from_utf8_lossy(&tree.stdout)
        );
    }
    assert_eq!(
        String::from_utf8_lossy(&shown.stdout),
        "from-first
",
        "the head's candidate carries the applied delta"
    );
}

/// THE MAIN-OWNED `workspace_effect`, live:
/// `first` writes `hello.txt` into `/work`, the `/work` apply lands the delta on
/// the execution's jj candidate, and the `commit` + `promote` effect stages
/// run IN THE MAIN — no capsule, no worker — fast-forwarding the operator's
/// `main` onto the validated candidate. The proof stage's required criterion
/// is what authorizes the promote, exactly as authoring requires.
///
/// Asserted from OUTSIDE kata's readers: `git log main` names a commit whose
/// tree carries `hello.txt` (read by git), the effect attempts are
/// `executor = 'main'` raw rows with no capsule, and the execution workspace
/// is torn down — promote is terminal.
const WORKSPACE_EFFECT_COMMIT_PROMOTE_PACK: &str = "
first = stage(
    id = \"first\",
    agent = \"shell\",
    sandbox = \"iso\",
    produces_files = [\"hello.txt\"],
    prompt = \"\"\"printf 'from-first\\n' > /work/hello.txt
printf '{\"wrote\": true}\\n'
\"\"\",
    outputs = { \"wrote\": \"bool\" },
)
proof = stage(
    id = \"proof\",
    agent = \"shell\",
    sandbox = \"iso\",
    depends_on = [first],
    prompt = \"\"\"printf '{\"status\": \"passed\", \"criteria\": [{\"criterion_id\": \"ok\", \"status\": \"passed\", \"stage_name\": \"proof\", \"evidence\": [\"checked\"]}]}\\n'
\"\"\",
)
commit = stage(
    id = \"commit\",
    agent = \"workspace_effect\",
    op = \"commit\",
    depends_on = [proof],
)
promote = stage(
    id = \"promote\",
    agent = \"workspace_effect\",
    op = \"promote\",
    depends_on = [commit],
)
workflow(
    \"workspace-effect-commit-promote\",
    root = [first],
    worktree_isolated = True,
    validation_criteria = [
        validation_criterion(
            \"ok\",
            description = \"the deterministic proof stage passed\",
            stage = \"proof\",
            required = True,
        ),
    ],
    sandbox_profiles = {
        \"iso\": sandbox_profile(
            workspace = \"rw\",
            net = \"offline\",
        ),
    },
)
";

/// Boot the oci main with `[vcs] jj_repo` answering the fixture repository,
/// return (root, main, repo, pack) — the shared fixture every workspace-effect live cell
/// starts from.
fn oci_main_on_repo(profile_pack: &str) -> (tempfile::TempDir, tempfile::TempDir, PathBuf) {
    let (fixture, root, repo) = oci_config_on_repo();
    let pack = root.path().join("pack.star");
    std::fs::write(&pack, profile_pack).unwrap();
    (fixture, root, repo)
}

/// The oci main's config with `[vcs] jj_repo` answering a fresh fixture
/// repository — for a cell that submits a checkout pack or rig by its repo path.
fn oci_config_on_repo() -> (tempfile::TempDir, tempfile::TempDir, PathBuf) {
    let fixture = tempfile::tempdir().expect("a fixture root");
    let repo = fixture.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    kata_test_utils::git::init_git_repo_at(&repo);
    let root = tempfile::tempdir().expect("an oci root");
    let config = write_config(root.path(), "oci");
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        format!(
            "{text}\n[vcs]\njj_repo = \"{}\"\ntrunk = \"main\"\n",
            repo.display()
        ),
    )
    .unwrap();
    (fixture, root, repo)
}

#[test]
#[ignore = "HOST-DEPENDENT like the differential (a certified rootless youki with its installed \
            AppArmor profile, a delegated user scope, the busybox closure realised, \
            `kata-provider-youki` built). Run alone, one test at a time: `cargo nextest run -p \
            kata -P live-smoke --test oci_main_live --run-ignored all`."]
fn a_workspace_effect_commit_then_promote_lands_on_trunk_under_oci_live() {
    let (fixture, root, repo) = oci_main_on_repo(WORKSPACE_EFFECT_COMMIT_PROMOTE_PACK);
    let trunk_before = {
        let out = hermetic_git_in(&repo)
            .args(["rev-parse", "main"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    let (route, _unseal) = provision_provider(root.path());
    let data = root.path().join("data");
    let pack = root.path().join("pack.star");
    let doc = {
        let main = Main::start(root.path(), &root.path().join("kata.toml"), true, &route);
        main.run(&pack)
    };
    assert_eq!(doc["status"], "completed", "oci: {doc}");

    // THE LANDED FACT, read by GIT: trunk holds a commit whose tree carries
    // hello.txt — the candidate `first`/`commit`/`promote` produced.
    let trunk_after = {
        let out = hermetic_git_in(&repo)
            .args(["rev-parse", "main"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    assert_ne!(
        trunk_before, trunk_after,
        "the promote fast-forwarded the operator's trunk"
    );
    let shown = hermetic_git_in(&repo)
        .args(["show", "main:hello.txt"])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&shown.stdout),
        "from-first\n",
        "trunk's tree carries the first stage's write: {}",
        String::from_utf8_lossy(&shown.stderr)
    );

    // THE MAIN-OWNED RECORD, raw: the two effect attempts are `main` executor
    // rows resolved `completed`, and neither stage minted a capsule.
    let conn = raw(&data);
    let main_attempts: i64 = conn
        .query_row(
            "SELECT count(*) FROM attempts WHERE executor = 'main' AND \
             stage_id IN ('commit','promote')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let capsules: i64 = conn
        .query_row("SELECT count(*) FROM capsules", [], |row| row.get(0))
        .unwrap();
    assert_eq!(main_attempts, 2, "both effects ran in the main");
    assert_eq!(
        capsules, 2,
        "exactly `first` and `proof` ran under a capsule — the effect stages minted none"
    );
    // And the execution workspace is torn down — promote is terminal.
    let agents = repo.join("agents");
    let leftovers: Vec<_> = std::fs::read_dir(&agents)
        .map(std::iter::Iterator::collect::<Vec<_>>)
        .unwrap_or_default();
    assert!(
        leftovers.is_empty(),
        "promote tore the execution workspace down: {leftovers:?}"
    );
    drop(fixture);
}

/// An INVOCATION PARAM, live, end to end: `kata run --param note=<text>` admits the
/// value, the shell stage's `run=` renders `{{ params.note | shquote }}` into its
/// command, the container writes it into `/work`, and `commit` + `promote` land it
/// on trunk.
///
/// Asserted from OUTSIDE kata: `git show main:params-note.txt` is the supplied
/// text, byte for byte — its quote, `$`, backtick, `;` and newline reached the file
/// as data, never as shell syntax.
const PARAMS_PROMOTE_PACK: &str = r#"
write = stage(
    id = "write",
    agent = "shell",
    sandbox = "iso",
    produces_files = ["params-note.txt"],
    prompt = """printf '%s\\n' {{ params.note | shquote }} > /work/params-note.txt
printf '{"wrote": true}\\n'
""",
    outputs = {"wrote": "bool"},
)
proof = stage(
    id = "proof",
    agent = "shell",
    sandbox = "iso",
    depends_on = [write],
    prompt = """printf '{"status": "passed", "criteria": [{"criterion_id": "ok", "status": "passed", "stage_name": "proof", "evidence": ["checked"]}]}\\n'
""",
)
commit = stage(id = "commit", agent = "workspace_effect", op = "commit", depends_on = [proof])
promote = stage(id = "promote", agent = "workspace_effect", op = "promote", depends_on = [commit])
workflow(
    "params-promote",
    root = [write],
    worktree_isolated = True,
    params = {"note": field("string")},
    validation_criteria = [
        validation_criterion(
            "ok",
            description = "the deterministic proof stage passed",
            stage = "proof",
            required = True,
        ),
    ],
    sandbox_profiles = {
        "iso": sandbox_profile(workspace = "rw", net = "offline"),
    },
)
"#;

/// The note the params cell supplies: a JSON string, so `--param` decodes the `\n`
/// into a real newline.
const PARAMS_PROMOTE_NOTE_JSON: &str = r#""it's $HOME `id`; echo pwned\nsecond line""#;

#[test]
#[ignore = "HOST-DEPENDENT like the differential (a certified rootless youki with its installed \
            AppArmor profile, a delegated user scope, the busybox closure realised, \
            `kata-provider-youki` built). Run alone, one test at a time: `cargo nextest run -p \
            kata -P live-smoke --test oci_main_live --run-ignored all`."]
fn an_invocation_param_renders_into_a_shell_stage_and_lands_on_trunk_live() {
    let (fixture, root, repo) = oci_main_on_repo(PARAMS_PROMOTE_PACK);
    let (route, _unseal) = provision_provider(root.path());
    let pack = root.path().join("pack.star");
    let doc = {
        let main = Main::start(root.path(), &root.path().join("kata.toml"), true, &route);
        let id = main.submit_with_params(&pack, &[("note", PARAMS_PROMOTE_NOTE_JSON)]);
        main.wait_terminal(&id)
    };
    assert_eq!(doc["status"], "completed", "oci: {doc}");

    let note: String = serde_json::from_str(PARAMS_PROMOTE_NOTE_JSON).unwrap();
    let shown = hermetic_git_in(&repo)
        .args(["show", "main:params-note.txt"])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&shown.stdout),
        format!("{note}\n"),
        "trunk carries the supplied param verbatim: {}",
        String::from_utf8_lossy(&shown.stderr)
    );
    drop(fixture);
}

/// The `park` effect, live: the candidate lands on `parked/<exec>-attempt0`
/// and the workspace is torn down — read out of git and the filesystem.
const WORKSPACE_EFFECT_PARK_PACK: &str = "
first = stage(
    id = \"first\",
    agent = \"shell\",
    sandbox = \"iso\",
    produces_files = [\"hello.txt\"],
    prompt = \"\"\"printf 'parked\\n' > /work/hello.txt
printf '{\"wrote\": true}\\n'
\"\"\",
    outputs = { \"wrote\": \"bool\" },
)
park = stage(
    id = \"park\",
    agent = \"workspace_effect\",
    op = \"park\",
    depends_on = [first],
)
workflow(
    \"workspace-effect-park\",
    root = [first],
    worktree_isolated = True,
    sandbox_profiles = {
        \"iso\": sandbox_profile(
            workspace = \"rw\",
            net = \"offline\",
        ),
    },
)
";

#[test]
#[ignore = "HOST-DEPENDENT like the differential. Run alone: `cargo nextest run -p kata \
            -P live-smoke --test oci_main_live --run-ignored all`."]
fn a_workspace_effect_park_preserves_the_candidate_under_oci_live() {
    let (fixture, root, repo) = oci_main_on_repo(WORKSPACE_EFFECT_PARK_PACK);
    let (route, _unseal) = provision_provider(root.path());
    let data = root.path().join("data");
    let pack = root.path().join("pack.star");
    let doc = {
        let main = Main::start(root.path(), &root.path().join("kata.toml"), true, &route);
        main.run(&pack)
    };
    assert_eq!(doc["status"], "completed", "oci: {doc}");
    let id = doc["id"].as_str().unwrap();
    // THE PARKED REF, read by git: `parked/<exec>-attempt0` names a commit
    // whose tree carries `parked\n` — the candidate preserved, not lost.
    let parked = hermetic_git_in(&repo)
        .args(["rev-parse", &format!("parked/{id}")])
        .output()
        .unwrap();
    assert!(
        parked.status.success(),
        "the parked ref exists: {}",
        String::from_utf8_lossy(&parked.stderr)
    );
    let parked_sha = String::from_utf8_lossy(&parked.stdout).trim().to_owned();
    let shown = hermetic_git_in(&repo)
        .args(["show", &format!("{parked_sha}:hello.txt")])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&shown.stdout),
        "parked\n",
        "the parked ref's tree carries the staged write"
    );
    // Trunk untouched — a park preserves, never lands.
    let trunk_has = hermetic_git_in(&repo)
        .args(["cat-file", "-e", "main:hello.txt"])
        .output()
        .unwrap();
    assert!(!trunk_has.status.success(), "a park never lands on trunk");
    let conn = raw(&data);
    let parked_attempts: i64 = conn
        .query_row(
            "SELECT count(*) FROM attempts WHERE executor = 'main' AND stage_id = 'park'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(parked_attempts, 1, "one main-resolved park attempt");
    drop(fixture);
}

/// The `forge_export` effect, live: the candidate, committed by a `commit`
/// effect (an export needs one among its ancestors), lands on `kata/<exec>` at a
/// LOCAL BARE `origin` — and the `gh` on the main's PATH is a shim that
/// records its argv, confirms the repository, serves the list call, and mints
/// one PR.
const WORKSPACE_EFFECT_EXPORT_PACK: &str = "
first = stage(
    id = \"first\",
    agent = \"shell\",
    sandbox = \"iso\",
    produces_files = [\"hello.txt\"],
    prompt = \"\"\"printf 'exported\\n' > /work/hello.txt
printf '{\"wrote\": true}\\n'
\"\"\",
    outputs = { \"wrote\": \"bool\" },
)
snap = stage(
    id = \"snap\",
    agent = \"workspace_effect\",
    op = \"commit\",
    depends_on = [first],
)
export = stage(
    id = \"export\",
    agent = \"workspace_effect\",
    op = \"forge_export\",
    title = \"cell: export the candidate\",
    depends_on = [snap],
)
workflow(
    \"workspace-effect-export\",
    root = [first],
    worktree_isolated = True,
    sandbox_profiles = {
        \"iso\": sandbox_profile(
            workspace = \"rw\",
            net = \"offline\",
        ),
    },
)
";

#[test]
#[ignore = "HOST-DEPENDENT like the differential. Run alone: `cargo nextest run -p kata \
            -P live-smoke --test oci_main_live --run-ignored all`."]
fn a_workspace_effect_forge_export_pushes_the_branch_and_opens_one_pr_live() {
    let (fixture, root, repo) = oci_main_on_repo(WORKSPACE_EFFECT_EXPORT_PACK);
    // The bare `origin` and the `gh` shim: `repo view <HOST/OWNER/REPO>` answers
    // that repository, `pr list` answers `[]`, `pr create`
    // records the argv and answers with a URL — invoked THROUGH the main's
    // PATH so the real GhCliForge drives it.
    let origin = fixture.path().join("origin.git");
    let out = hermetic_git_in(fixture.path())
        .args(["init", "--bare", origin.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    kata_test_utils::git::add_forge_remote(&repo, "origin", &origin, "forge.test/o/r");
    let shim_dir = fixture.path().join("shim");
    std::fs::create_dir(&shim_dir).unwrap();
    let gh_log = fixture.path().join("gh-invocations.log");
    std::fs::write(
        shim_dir.join("gh"),
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> {}\ncase \"$1 $2\" in\n  \
             'pr list') printf '[]\\n' ;;\n  'pr create') printf \
             'https://forge.test/pull/7\\n' ;;\n  'repo view') printf \
             '{{\"nameWithOwner\":\"%s\"}}\\n' \"${{3#*/}}\" ;;\nesac\n",
            gh_log.display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(shim_dir.join("gh"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
    }
    let (mut route, _unseal) = provision_provider(root.path());
    let path = format!(
        "{}:{}",
        shim_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    route.push(("PATH".to_owned(), path));
    let pack = root.path().join("pack.star");
    let doc = {
        let main = Main::start(root.path(), &root.path().join("kata.toml"), true, &route);
        main.run(&pack)
    };
    assert_eq!(doc["status"], "completed", "oci: {doc}");
    let id = doc["id"].as_str().unwrap();
    // THE BRANCH, read from the bare remote's own refs — never through kata.
    let remote_head = hermetic_git_in(&repo)
        .args(["ls-remote", "origin", &format!("refs/heads/kata/{id}")])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&remote_head.stdout);
    assert!(
        stdout.contains(&format!("refs/heads/kata/{id}")),
        "the export pushed kata/{id}: {stdout}"
    );
    let pushed_sha = stdout.split_whitespace().next().unwrap().to_owned();
    let shown = hermetic_git_in(&repo)
        .args(["show", &format!("{pushed_sha}:hello.txt")])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&shown.stdout),
        "exported\n",
        "the pushed branch carries the staged write"
    );
    // THE PR: the shim's argv log shows the repository's confirmation, `pr
    // list`, then ONE `pr create`.
    let invocations = std::fs::read_to_string(&gh_log).unwrap_or_default();
    assert_eq!(
        invocations
            .lines()
            .filter(|line| line.starts_with("pr list"))
            .count(),
        1,
        "the idempotent list ran once: {invocations}"
    );
    assert_eq!(
        invocations
            .lines()
            .filter(|line| line.starts_with("pr create"))
            .count(),
        1,
        "exactly one PR was created: {invocations}"
    );
    assert_eq!(
        invocations.lines().next(),
        Some("repo view forge.test/o/r --json nameWithOwner"),
        "the push waits on gh confirming the push remote's repository: {invocations}"
    );
    assert!(
        invocations
            .lines()
            .filter(|line| line.starts_with("pr "))
            .all(|line| line.contains(" --repo forge.test/o/r ")),
        "every gh call names the push remote's repository: {invocations}"
    );
    drop(fixture);
}

/// The `commit` rig, by path.
const WORKSPACE_COMMIT_SMOKE_PACK: &str = "workflows/smoke/workspace-commit-smoke.star";

/// THE `workflows/smoke` RIG `workspace-commit-smoke`, live: `dirty` writes a line into `/work` and
/// leaves it uncommitted, the main's `commit` effect finalizes the candidate, and
/// `observe` checks the claim against the `{{ workspace.* }}` namespace rendered on the
/// host (`head_sha`, `changed_files` from the execution's base, a `diff_lines()` revset).
/// It is the one cell that runs that namespace through a real main — the admission
/// that records the head row, the apply driver that lands the capsule's delta, the
/// effect, and the dispatch-time render — rather than the host-free rig's verbs.
///
/// Asserted from OUTSIDE kata: `exec-<id>` names a commit whose
/// `workspace-commit-smoke.txt` is exactly the line `dirty` reported, whose parent is
/// the trunk the execution forked from, and which `observe` reported as the recorded
/// head; trunk itself is untouched (a commit lands nothing); the effect is one
/// `executor = 'main'` attempt and only `dirty` and `observe` ran under a capsule.
#[test]
#[ignore = "HOST-DEPENDENT like the rest of this binary (a certified rootless youki with its \
            installed AppArmor profile, a delegated user scope, the busybox closure realised, \
            `kata-provider-youki` built). L1: `just oci-live-smoke`; alone: `cargo nextest \
            run -p kata -P live-smoke --test oci_main_live --run-ignored all -E \
            'test(=the_shipped_commit_smoke_commits_the_dirty_write_and_observes_it_live)'`."]
fn the_shipped_commit_smoke_commits_the_dirty_write_and_observes_it_live() {
    let (fixture, root, repo) = oci_config_on_repo();
    let git = |args: &[&str]| {
        let out = hermetic_git_in(&repo).args(args).output().unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let trunk_before = git(&["rev-parse", "main"]).trim().to_owned();
    let (route, _unseal) = provision_provider(root.path());
    let data = root.path().join("data");
    let doc = {
        let main = Main::start(root.path(), &root.path().join("kata.toml"), true, &route);
        main.run(Path::new(WORKSPACE_COMMIT_SMOKE_PACK))
    };
    assert_eq!(doc["status"], "completed", "oci: {doc}");
    let id = doc["id"].as_str().expect("an id");
    let line = doc["outputs"]["dirty"]["parsed"]["line"]
        .as_str()
        .unwrap_or_else(|| panic!("dirty reports its line: {doc}"));
    let observed = &doc["outputs"]["observe"]["parsed"];
    assert_eq!(observed["observed"], "committed", "{doc}");
    assert_eq!(observed["worktree"], "live", "{doc}");

    // THE COMMIT, read by git: `exec-<id>` holds exactly the dirty line, on trunk.
    let committed = git(&["rev-parse", &format!("exec-{id}")]).trim().to_owned();
    assert_eq!(
        observed["commit_sha"], committed,
        "observe's recorded head is the commit `exec-<id>` names"
    );
    assert_eq!(
        git(&["show", &format!("{committed}:workspace-commit-smoke.txt")]),
        format!("{line}\n"),
        "the commit holds the line `dirty` left uncommitted"
    );
    assert_eq!(
        git(&["rev-parse", &format!("{committed}^")]).trim(),
        trunk_before,
        "the commit sits directly on the trunk the execution forked from"
    );
    assert_eq!(
        git(&["rev-parse", "main"]).trim(),
        trunk_before,
        "a commit lands nothing on trunk"
    );

    // THE MAIN-OWNED RECORD, raw.
    let conn = raw(&data);
    let main_commits: i64 = conn
        .query_row(
            "SELECT count(*) FROM attempts WHERE executor = 'main' AND stage_id = 'commit'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let capsules: i64 = conn
        .query_row("SELECT count(*) FROM capsules", [], |row| row.get(0))
        .unwrap();
    assert_eq!(main_commits, 1, "the commit effect ran once, in the main");
    assert_eq!(
        capsules, 2,
        "only `dirty` and `observe` ran under a capsule"
    );
    println!("WORKSPACE-COMMIT-SMOKE oci={id} commit={committed} trunk={trunk_before}");
    drop(fixture);
}

/// The durable-timer rig, by path.
const SLEEP_PACK: &str = "workflows/smoke/sleep-smoke.star";
/// Its sleep stage and length.
const SLEEP_STAGE: &str = "nap";

/// The main-side timer's durable facts, read RAW off `operational.db`: `(executor, claim
/// recorded_at_ms, the deadline its park frame recorded, the accepting transition's seq and
/// recorded_at_ms)`.
fn raw_timer(data: &Path, stage: &str) -> (String, i64, i64, i64, i64) {
    raw(data)
        .query_row(
            "SELECT a.executor,
                    (SELECT recorded_at_ms FROM transitions
                      WHERE attempt_id = a.attempt_id AND kind = 'main_claimed'),
                    (SELECT json_extract(payload_json, '$.wait_deadline_ms') FROM transitions
                      WHERE attempt_id = a.attempt_id AND kind = 'main_parked'),
                    t.seq, t.recorded_at_ms
               FROM attempts a
               JOIN occurrences o ON o.accepted_attempt_id = a.attempt_id
               JOIN transitions t ON t.attempt_id = a.attempt_id AND t.resulting_state = 'completed'
              WHERE a.stage_id = ?1",
            [stage],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .unwrap_or_else(|error| panic!("{stage} is one accepted main attempt: {error}"))
}

/// `(attempts, completed transitions, first transition seq)` of `stage`, read raw.
fn raw_stage_runs(data: &Path, stage: &str) -> (i64, i64, i64) {
    raw(data)
        .query_row(
            "SELECT (SELECT count(*) FROM attempts WHERE stage_id = ?1),
                    (SELECT count(*) FROM transitions t JOIN attempts a
                        ON a.attempt_id = t.attempt_id
                      WHERE a.stage_id = ?1 AND t.resulting_state = 'completed'),
                    (SELECT coalesce(min(t.seq), 0) FROM transitions t JOIN attempts a
                        ON a.attempt_id = t.attempt_id WHERE a.stage_id = ?1)",
            [stage],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
}

/// A MAIN SIGKILLED MID-SLEEP: an `oci` main run as a transient
/// service parks a 20 s durable timer; once the RAW plane shows it parked, the main is
/// `SIGKILL`ed. A second main over the same data directory completes the execution, and,
/// read raw: the timer is still ONE attempt, its deadline unchanged by the restart and its
/// acceptance at or after it; the successor `after` ran EXACTLY ONCE (one attempt, one
/// completion), after the acceptance; and `before` was not re-run.
#[test]
#[ignore = "HOST-DEPENDENT like the differential (a certified rootless youki with its installed \
            AppArmor profile, a systemd user manager that delegates, the busybox closure \
            realised, `kata-provider-youki` built). Run alone, one test at a time: `cargo nextest \
            run -p kata -P live-smoke --test oci_main_live --run-ignored \
            all`."]
fn a_main_killed_mid_sleep_runs_the_successor_exactly_once_live() {
    let root = tempfile::tempdir().expect("an oci root");
    let config = write_config(root.path(), "oci");
    let (route, _unseal) = provision_provider(root.path());
    let data = root.path().join("data");
    let pack = root.path().join("kill-mid-sleep.star");
    let shipped = std::fs::read_to_string(repo_root().join(SLEEP_PACK)).unwrap();
    assert_eq!(shipped.matches("for_ms = 3000").count(), 1);
    std::fs::write(
        &pack,
        shipped
            .replace("for_ms = 3000", "for_ms = 20000")
            .replace("\"sleep-smoke\"", "\"kill-mid-sleep\""),
    )
    .unwrap();
    let unit = format!("kata-kill-mid-sleep-{}", std::process::id());

    let first = ServiceMain::start(root.path(), &config, &format!("{unit}-a"), &route);
    let submitted = kata()
        .args(["--api-url", &first.url, "run"])
        .arg(&pack)
        .arg("--submit")
        .output()
        .expect("kata run --submit runs");
    let stdout = String::from_utf8_lossy(&submitted.stdout).into_owned();
    let id = stdout
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .and_then(|doc| doc["id"].as_str().map(str::to_owned))
        .unwrap_or_else(|| panic!("the submit printed no execution id: {stdout}"));
    let parked = || -> Option<i64> {
        raw(&data)
            .query_row(
                "SELECT json_extract(t.payload_json, '$.wait_deadline_ms')
                   FROM attempts a
                   JOIN attempt_projection p ON p.execution_id = a.execution_id
                    AND p.stage_id = a.stage_id AND p.attempt_ordinal = a.attempt_ordinal
                   JOIN transitions t ON t.attempt_id = a.attempt_id AND t.kind = 'main_parked'
                  WHERE a.stage_id = ?1 AND p.state = 'awaiting_timer'",
                [SLEEP_STAGE],
                |row| row.get(0),
            )
            .ok()
    };
    wait_until(
        "the sleep to park main-side",
        Duration::from_secs(180),
        || parked().is_some(),
    );
    let deadline_before_kill = parked().expect("parked");
    let killed = Command::new("kill")
        .args(["-KILL", &first.main_pid().to_string()])
        .status()
        .expect("kill runs");
    assert!(killed.success(), "the main was SIGKILLed");
    let killed_at = Instant::now();
    drop(first);

    let second = ServiceMain::start(root.path(), &config, &format!("{unit}-b"), &route);
    let mut shown = serde_json::Value::Null;
    wait_until(
        "the execution to reach a terminal status on the next main",
        Duration::from_secs(180),
        || {
            let output = kata()
                .args(["--api-url", &second.url, "run", "show", &id])
                .output()
                .expect("kata run show runs");
            shown = serde_json::from_slice(&output.stdout).unwrap_or_default();
            matches!(
                shown["status"].as_str(),
                Some("completed" | "failed" | "cancelled" | "timed_out")
            )
        },
    );
    let restart_to_terminal = killed_at.elapsed();
    drop(second);
    assert_eq!(shown["status"], "completed", "{shown}");
    assert_eq!(
        shown["outputs"]["after"]["parsed"]["carried"], "before-value",
        "{shown}"
    );

    let (executor, claimed_at, deadline, accept_seq, accepted_at) = raw_timer(&data, SLEEP_STAGE);
    assert_eq!(executor, "main");
    assert_eq!(
        deadline, deadline_before_kill,
        "the restart did not re-anchor the deadline"
    );
    assert_eq!(deadline, claimed_at + 20_000);
    assert!(
        accepted_at >= deadline,
        "accepted at {accepted_at}, deadline {deadline}"
    );
    assert_eq!(raw_stage_runs(&data, SLEEP_STAGE).0, 1, "one timer attempt");
    let (after_attempts, after_completed, after_first) = raw_stage_runs(&data, "after");
    assert_eq!(
        (after_attempts, after_completed),
        (1, 1),
        "the successor ran exactly once"
    );
    assert!(
        after_first > accept_seq,
        "after started after the acceptance"
    );
    assert_eq!(
        raw_stage_runs(&data, "before").0,
        1,
        "before was not re-run"
    );
    println!(
        "KILL-MID-SLEEP execution={id} deadline={deadline} accepted_at={accepted_at} \
         late_by_ms={} restart_to_terminal={restart_to_terminal:?} after_runs=1",
        accepted_at - deadline
    );
}

/// The sleep only the cancel cell's capsule runs, so `pgrep` finds its container alone.
const CANCEL_CELL_SLEEP: &str = "sleep 297";

/// AN OPERATOR CANCEL STOPS A RUNNING CAPSULE. A capsule sleeping for
/// minutes on a durable `oci` main; once the HOST sees its `sleep`, `kata run cancel`
/// (the client path) answers `assignments_asked_to_stop: 1`. Then, off the host and raw:
/// the container's process and cgroup are gone, the capsule attempt's last transition is
/// `cancelled`, the execution reaches a terminal status, and no runtime state remains with
/// the main up or after it stopped, and the execution's durable lifecycle row reads
/// `cancelled`, and the wire `status` serves it as `cancelled`. A cancel or a TERMINAL
/// derivation that read only the non-capsule assignment population would ask nothing (the
/// container runs on) or publish `failed`.
#[test]
#[ignore = "HOST-DEPENDENT like the differential (a certified rootless youki with its installed \
            AppArmor profile, a delegated user scope, the busybox closure realised, \
            `kata-provider-youki` built). Run alone, one test at a time: `cargo nextest run -p \
            kata -P live-smoke --test oci_main_live --run-ignored all`."]
fn an_operator_cancel_stops_a_running_capsule_live() {
    assert!(
        pgrep(CANCEL_CELL_SLEEP).is_empty(),
        "the premise: nothing on this host already runs `{CANCEL_CELL_SLEEP}`"
    );
    let root = tempfile::tempdir().expect("an oci root");
    let config = write_config(root.path(), "oci");
    let (route, _unseal) = provision_provider(root.path());
    let data = root.path().join("data");
    let worker_state = data.join("oci-worker-state");
    let pack = root.path().join("cancel-capsule.star");
    std::fs::write(
        &pack,
        format!(
            "probe = stage(\n    id = \"probe\",\n    agent = \"shell\",\n    sandbox = \"iso\",\n    \
             timeout_ms = 600000,\n    prompt = \"{CANCEL_CELL_SLEEP}\",\n)\n\nworkflow(\n    \
             \"cancel-capsule\",\n    root = [probe],\n    sandbox_profiles = {{\"iso\": \
             sandbox_profile(workspace = \"rw\", net = \"offline\")}},\n)\n"
        ),
    )
    .unwrap();
    let providers_before = cgroup_dirs("kata.provider.*");
    let (id, container, cancel_ack, status) = {
        let main = Main::start(root.path(), &config, true, &route);
        let submitted = kata()
            .args(["--api-url", &main.url, "run"])
            .arg(&pack)
            .arg("--submit")
            .output()
            .expect("kata run --submit runs");
        let stdout = String::from_utf8_lossy(&submitted.stdout).into_owned();
        let id = stdout
            .lines()
            .rev()
            .find_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .and_then(|doc| doc["id"].as_str().map(str::to_owned))
            .unwrap_or_else(|| panic!("the submit printed no execution id: {stdout}"));
        wait_until(
            "the container's `sleep` to appear in the host's process table",
            Duration::from_secs(180),
            || !pgrep(CANCEL_CELL_SLEEP).is_empty(),
        );
        let capsule: Vec<u8> = raw(&data)
            .query_row("SELECT capsule_id FROM capsules", [], |row| row.get(0))
            .expect("exactly one capsule was authorized");
        let container = format!("kata-{}", hex::encode(capsule));
        let cancelled = kata()
            .args(["--api-url", &main.url, "run", "cancel", &id])
            .output()
            .expect("kata run cancel runs");
        assert!(
            cancelled.status.success(),
            "{}",
            String::from_utf8_lossy(&cancelled.stderr)
        );
        let cancel_ack: serde_json::Value = serde_json::from_slice(&cancelled.stdout)
            .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&cancelled.stdout)));
        wait_until(
            "the container's `sleep` to leave the process table after the cancel",
            Duration::from_secs(120),
            || pgrep(CANCEL_CELL_SLEEP).is_empty(),
        );
        wait_until(
            "the container's cgroup to be removed after the cancel",
            Duration::from_secs(120),
            || cgroup_dirs(&format!("kata.oci.{container}")).is_empty(),
        );
        let mut shown = serde_json::Value::Null;
        wait_until(
            "the cancelled execution to reach a terminal status",
            Duration::from_secs(120),
            || {
                let output = kata()
                    .args(["--api-url", &main.url, "run", "show", &id])
                    .output()
                    .expect("kata run show runs");
                shown = serde_json::from_slice(&output.stdout).unwrap_or_default();
                matches!(
                    shown["status"].as_str(),
                    Some("completed" | "failed" | "cancelled" | "timed_out")
                )
            },
        );
        let residue = runtime_residue(&worker_state, &container, &providers_before);
        assert!(residue.is_empty(), "main up:\n{}", describe(&residue));
        (id, container, cancel_ack, shown["status"].clone())
    };
    let residue = runtime_residue(&worker_state, &container, &providers_before);
    assert!(residue.is_empty(), "main stopped:\n{}", describe(&residue));
    assert_eq!(cancel_ack["assignments_asked_to_stop"], 1, "{cancel_ack}");
    let (state, reason): (String, String) = raw(&data)
        .query_row(
            "SELECT t.resulting_state, coalesce(json_extract(t.payload_json, '$.reason'), '') \
               FROM transitions t JOIN attempts a ON a.attempt_id = t.attempt_id \
              WHERE a.stage_id = 'probe' ORDER BY t.seq DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the capsule attempt's last transition");
    assert_eq!(state, "cancelled", "{reason}");
    // The DURABLE lifecycle, raw — the oracle that does not share the wire
    // projection; the record's `status` is asserted `cancelled` below.
    let lifecycle: Vec<String> = {
        let conn = raw(&data);
        let mut statement = conn
            .prepare("SELECT state FROM execution_lifecycle")
            .unwrap();
        statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert_eq!(
        lifecycle,
        vec!["cancelled".to_string()],
        "the execution publishes `cancelled`: its only cancelled stage is a capsule, which \
         the terminal derivation reads (served as {status})"
    );
    assert_eq!(
        status, "cancelled",
        "the wire `status` serves the cancelled terminal"
    );
    println!(
        "CANCEL-CAPSULE execution={id} container={container} ack={cancel_ack} status={status} \
         lifecycle={lifecycle:?} attempt_state={state} reason=\"{reason}\" runtime_residue=none"
    );
}

/// The reuse rig (`capsule-reuse-smoke`): a `content_cache` shell stage that writes
/// `/out/result.txt` from `/work`.
const REUSE_PACK: &str = "workflows/smoke/capsule-reuse-smoke.star";
const REUSE_STAGE: &str = "digest";

/// The `sha256sum` of `bytes`, computed by the HOST's tool over stdin.
fn host_sha256(bytes: &[u8]) -> String {
    use std::io::Write as _;
    let mut child = Command::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("sha256sum runs");
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    let output = child.wait_with_output().expect("sha256sum answers");
    assert!(output.status.success());
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .expect("a digest")
        .to_owned()
}

/// Execution `id`'s accepted result: `(accepting executor, result artifact id hex, the
/// `result.txt` member's bytes)`, read raw off `operational.db` and `cas.db`.
fn accepted_out(data_dir: &Path, id: &str) -> (String, String, Vec<u8>) {
    let conn = raw(data_dir);
    let execution = ulid::Ulid::from_string(id).expect("an execution id");
    let (executor, artifact): (String, String) = conn
        .query_row(
            "SELECT a.executor, json_extract(t.payload_json, '$.output.result_artifact_id')
               FROM occurrences o
               JOIN attempts a ON a.attempt_id = o.accepted_attempt_id
               JOIN transitions t ON t.attempt_id = a.attempt_id
                                 AND t.resulting_state = 'completed'
              WHERE o.execution_id = ?1",
            [execution.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the execution's occurrence is accepted, naming its result");
    let object: Vec<u8> = conn
        .query_row(
            "SELECT object_id FROM artifacts WHERE artifact_id = ?1 AND kind = 'tree'",
            [hex::decode(&artifact).expect("hex").as_slice()],
            |row| row.get(0),
        )
        .expect("the result artifact is a tree row");
    let manifest: serde_json::Value =
        serde_json::from_slice(&raw_cas_object(data_dir, &object)).expect("a JSON manifest");
    let entries = manifest["entries"].as_array().expect("manifest entries");
    let member = entries
        .iter()
        // Manifest v2 nests the payload under `node`: a file carries
        // `object`/`size_bytes`, a symlink carries `target` and names no object —
        // it is skipped, not `expect`ed, so a link at this path reads as its own
        // truth rather than as a missing member.
        .find(|entry| entry["path"] == "result.txt" && entry["node"]["kind"] == "file")
        .unwrap_or_else(|| panic!("the /out tree holds a result.txt FILE: {manifest}"));
    let member_object =
        hex::decode(member["node"]["object"].as_str().expect("an object hex")).expect("hex");
    (executor, artifact, raw_cas_object(data_dir, &member_object))
}

/// **THE CAPSULE CONTENT CACHE, LIVE**: the reuse rig
/// submitted TWICE to ONE durable `oci` main.
///
/// Run 1 (the positive control) runs its container: one capsule is authorized, its
/// attempt is a WORKER attempt that reached `running` (the worker's start checkpoint), and
/// the `/out/result.txt` it adopted carries the header line only the container's command
/// writes. Run 2 ADOPTS run 1's result and runs nothing — read off the host and the planes,
/// never off kata's answer: no directory ever appears under `<worker_state>/attempts`
/// while it runs (polled), no `kata.oci.*` cgroup exists, the pinned youki's `list` over
/// every provider state root names no container, and raw SQLite shows run 2's occurrence
/// accepted by its one `executor = 'main'` attempt with no capsule or command row. The
/// adopted `/out/result.txt` blob's `sha256sum` equals run 1's, and both runs' `kata run
/// show` serve the same `parsed` output, run 2's naming run 1 as `reused_from`.
#[test]
#[ignore = "HOST-DEPENDENT like the differential (a certified rootless youki with its installed \
            AppArmor profile, a delegated user scope, the busybox closure realised, \
            `kata-provider-youki` built). Run alone, one test at a time: `cargo nextest run -p \
            kata -P live-smoke --test oci_main_live --run-ignored all`."]
fn a_second_equal_capsule_adopts_the_first_result_and_runs_no_container_live() {
    let root = tempfile::tempdir().expect("an oci root");
    let config = write_config(root.path(), "oci");
    let (route, _unseal) = provision_provider(root.path());
    let data = root.path().join("data");
    let worker_state = data.join("oci-worker-state");
    let attempts_dir = worker_state.join("attempts");
    let oci_before = cgroup_dirs("kata.oci.*");
    let providers_before = cgroup_dirs("kata.provider.*");
    let main = Main::start(root.path(), &config, true, &route);

    // -- RUN 1: the container runs (the positive control) ------------------------------
    let first = main.run(Path::new(REUSE_PACK));
    assert_eq!(first["status"], "completed", "run 1: {first}");
    let first_id = first["id"].as_str().expect("an id").to_owned();
    let conn = raw(&data);
    let (capsules, first_running): (i64, i64) = conn
        .query_row(
            "SELECT (SELECT count(*) FROM capsules),
                    (SELECT count(*) FROM transitions t JOIN attempts a
                        ON a.attempt_id = t.attempt_id
                      WHERE a.execution_id = ?1 AND a.executor = 'worker'
                        AND t.resulting_state = 'running')",
            [ulid::Ulid::from_string(&first_id)
                .unwrap()
                .to_bytes()
                .as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(capsules, 1, "run 1 authorized one capsule");
    assert!(
        first_running >= 1,
        "run 1's worker attempt reached `running`: its container started"
    );
    let (first_executor, first_artifact, first_blob) = accepted_out(&data, &first_id);
    assert_eq!(first_executor, "worker");
    assert!(
        String::from_utf8_lossy(&first_blob)
            .starts_with("capsule-reuse-smoke: sha256 of every /work file\n"),
        "run 1's /out/result.txt is the container's own output: {:?}",
        String::from_utf8_lossy(&first_blob)
    );

    // -- RUN 2: adopts, runs nothing ----------------------------------------------------
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let poller = {
        let seen = std::sync::Arc::clone(&seen);
        let stop = std::sync::Arc::clone(&stop);
        let attempts_dir = attempts_dir.clone();
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                if let Ok(entries) = std::fs::read_dir(&attempts_dir) {
                    let mut seen = seen.lock().unwrap();
                    for entry in entries.flatten() {
                        let name = entry.file_name().to_string_lossy().into_owned();
                        if !seen.contains(&name) {
                            seen.push(name);
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        })
    };
    let second = main.run(Path::new(REUSE_PACK));
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    poller.join().unwrap();
    assert_eq!(second["status"], "completed", "run 2: {second}");
    let second_id = second["id"].as_str().expect("an id").to_owned();
    assert!(
        seen.lock().unwrap().is_empty(),
        "no attempt directory appeared under {} during run 2: {:?}",
        attempts_dir.display(),
        seen.lock().unwrap()
    );
    let new_oci: Vec<String> = cgroup_dirs("kata.oci.*")
        .into_iter()
        .filter(|dir| !oci_before.contains(dir))
        .collect();
    assert!(new_oci.is_empty(), "no kata.oci.* cgroup: {new_oci:?}");
    let first_container = format!(
        "kata-{}",
        hex::encode(
            conn.query_row("SELECT capsule_id FROM capsules", [], |row| row
                .get::<_, Vec<u8>>(0))
                .unwrap()
        )
    );
    let residue = runtime_residue(&worker_state, &first_container, &providers_before);
    assert!(
        residue.is_empty(),
        "no runtime state with the main up after run 2:\n{}",
        describe(&residue)
    );
    let second_execution = ulid::Ulid::from_string(&second_id).unwrap();
    let (capsules_after, second_attempts, second_main, second_commands): (i64, i64, i64, i64) =
        conn.query_row(
            "SELECT (SELECT count(*) FROM capsules),
                    (SELECT count(*) FROM attempts WHERE execution_id = ?1 \
                       AND stage_id NOT LIKE '#apply/%'),
                    (SELECT count(*) FROM attempts WHERE execution_id = ?1 AND executor = 'main' \
                       AND stage_id NOT LIKE '#apply/%'),
                    (SELECT count(*) FROM attempt_commands WHERE attempt_id IN
                        (SELECT attempt_id FROM attempts WHERE execution_id = ?1))",
            [second_execution.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        (
            capsules_after,
            second_attempts,
            second_main,
            second_commands
        ),
        (1, 1, 1, 0),
        "run 2: no new capsule, ONE attempt and it is main-resolved, no command"
    );
    let (second_executor, second_artifact, second_blob) = accepted_out(&data, &second_id);
    assert_eq!(second_executor, "main");
    assert_eq!(second_artifact, first_artifact, "the SAME result artifact");
    let first_sha = host_sha256(&first_blob);
    let second_sha = host_sha256(&second_blob);
    assert_eq!(
        second_sha, first_sha,
        "the adopted /out blob is run 1's, byte for byte"
    );
    assert_eq!(
        second["outputs"][REUSE_STAGE]["parsed"], first["outputs"][REUSE_STAGE]["parsed"],
        "one parsed output"
    );
    assert_eq!(
        second["outputs"][REUSE_STAGE]["reused_from"]["execution"], first_id,
        "run 2 names its source: {second}"
    );
    // The main kept AUTHORITY over both executions: a chain reader that refuses the reused
    // stage's amended main attempt logs an ERROR and loses the execution.
    let log = std::fs::read_to_string(&main.log).expect("the main's log");
    let refused: Vec<&str> = log
        .lines()
        .filter(|line| line.contains("ERROR") || line.contains("assignment population"))
        .collect();
    assert!(
        refused.is_empty(),
        "the main logged a refusal over the reused execution:\n{}",
        refused.join("\n")
    );
    drop(main);
    let residue = runtime_residue(&worker_state, &first_container, &providers_before);
    assert!(
        residue.is_empty(),
        "no runtime state with the main stopped:\n{}",
        describe(&residue)
    );
    println!(
        "CAPSULE-REUSE run1={first_id} run2={second_id} artifact={first_artifact} \
         out_sha256={first_sha} run2_attempt_dirs=0 run2_commands=0 runtime_residue=none"
    );
}

impl Main {}

/// The COMMITTED-BASE `/work` head, end to end
/// on an installed `oci` main inside a real rootless container.
///
/// The host-free cells prove the ADMISSION half (the head row, the CAS
/// publication, the manifest's node kinds); this cell proves the half only a
/// running container can: the worker materializes the RECORDED artifact at
/// `/work`, and inside the container a committed regular file reads, a
/// committed executable carries its bit, a committed symlink resolves — while
/// the two dirty shapes the operator checkout holds the whole run (an
/// untracked file and an uncommitted edit to a tracked one) never appear. The
/// durable side is read RAW: one `execution_work_tree_heads` row, the
/// occurrence bound to the head's artifact, and no second execution tree
/// artifact — the isolated producer mints no per-attempt walk receipt.
///
/// The pack is written by the test (it is not a `workflows/smoke` rig): one shell
/// stage under `workspace = "ro"` probes `/work` and reports the five legs.
///
/// `worktree_isolated` on an `oci` main answers `[vcs] jj_repo` — the
/// configured repository authority, never process CWD — so the config below
/// points it at the fixture and pins `trunk = "main"` (the fixture holds
/// exactly one branch, but the pin makes the read independent of the
/// resolver's precedence).
#[test]
#[ignore = "HOST-DEPENDENT like the differential (a certified rootless youki with its installed \
            AppArmor profile, a delegated user scope, the busybox closure realised, \
            `kata-provider-youki` built). Run alone: `cargo nextest run -p kata -P live-smoke \
            --test oci_main_live --run-ignored all`."]
fn an_isolated_execution_maps_its_recorded_base_head_inside_a_container_live() {
    // -- THE REPOSITORY THE HOST WROTE ---------------------------------------
    // Every node kind the conversion carries, committed by the host's own git:
    // committed.txt (regular), run.sh (mode 755), latest (symlink). Then the
    // checkout goes DIRTY for the whole run: an untracked file plus an
    // uncommitted edit to committed.txt — the two shapes that must never be
    // inputs.
    let fixture = tempfile::tempdir().expect("a fixture root");
    let repo = fixture.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    kata_test_utils::git::init_git_repo_at(&repo);
    std::fs::write(repo.join("committed.txt"), b"committed-bytes\n").unwrap();
    std::fs::write(repo.join("run.sh"), b"#!/bin/sh\nexit 0\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(repo.join("run.sh"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
    }
    std::os::unix::fs::symlink("committed.txt", repo.join("latest")).unwrap();
    kata_test_utils::git::run_git(&repo, &["add", "-A"]);
    kata_test_utils::git::run_git(&repo, &["commit", "-q", "-m", "the committed base"]);
    std::fs::write(repo.join("uncommitted.txt"), b"never an input\n").unwrap();
    std::fs::write(
        repo.join("committed.txt"),
        b"committed-bytes\nedited-after-commit\n",
    )
    .unwrap();

    // -- THE PACK: one stage reporting five legs out of /work -----------------
    let pack = fixture.path().join("work-head-live.star");
    std::fs::write(
        &pack,
        "probe = stage(\n\
         \x20   id = \"probe\",\n\
         \x20   agent = \"shell\",\n\
         \x20   sandbox = \"read-work\",\n\
         \x20   prompt = \"\"\"set -eu\n\
         COMMITTED=false; test -f /work/committed.txt && COMMITTED=true\n\
         EXEC=false; test -x /work/run.sh && EXEC=true\n\
         LINK=false; test -L /work/latest && LINK=true\n\
         UNCOMMITTED_ABSENT=true; test -e /work/uncommitted.txt && UNCOMMITTED_ABSENT=false\n\
         DIRTY_ABSENT=true; grep -q 'edited-after-commit' /work/committed.txt && DIRTY_ABSENT=false\n\
         printf '{\"committed\": %s, \"exec\": %s, \"symlink\": %s, \"uncommitted_absent\": %s, \"dirty_absent\": %s}\\\\n' \\\n\
         \x20   \"$COMMITTED\" \"$EXEC\" \"$LINK\" \"$UNCOMMITTED_ABSENT\" \"$DIRTY_ABSENT\"\n\
         \"\"\",\n\
         \x20   outputs = {\n\
         \x20       \"committed\": \"bool\",\n\
         \x20       \"exec\": \"bool\",\n\
         \x20       \"symlink\": \"bool\",\n\
         \x20       \"uncommitted_absent\": \"bool\",\n\
         \x20       \"dirty_absent\": \"bool\",\n\
         \x20   },\n\
         )\n\n\
         workflow(\n\
         \x20   \"work-head-live\",\n\
         \x20   root = [probe],\n\
         \x20   worktree_isolated = True,\n\
         \x20   sandbox_profiles = {\n\
         \x20       \"read-work\": sandbox_profile(workspace = \"ro\", net = \"offline\"),\n\
         \x20   },\n\
         )\n",
    )
    .unwrap();

    // -- THE OCI MAIN: configured at the fixture repository -------------------
    let oci_root = tempfile::tempdir().expect("an oci root");
    let config = write_config(oci_root.path(), "oci");
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        format!(
            "{text}\n[vcs]\njj_repo = \"{}\"\ntrunk = \"main\"\n",
            repo.display()
        ),
    )
    .unwrap();
    let (route, _unseal) = provision_provider(oci_root.path());
    let oci_data = oci_root.path().join("data");
    let worker_state = oci_data.join("oci-worker-state");
    let providers_before = cgroup_dirs("kata.provider.*");
    let (doc, container) = {
        let main = Main::start(oci_root.path(), &config, true, &route);
        let doc = main.run(&pack);
        let capsule: Vec<u8> = raw(&oci_data)
            .query_row("SELECT capsule_id FROM capsules", [], |row| row.get(0))
            .expect("exactly one capsule was authorized");
        let container = format!("kata-{}", hex::encode(capsule));
        let residue = runtime_residue(&worker_state, &container, &providers_before);
        assert!(
            residue.is_empty(),
            "the finished capsule left runtime state behind while its main is up:\n{}",
            describe(&residue)
        );
        (doc, container)
    };
    let residue = runtime_residue(&worker_state, &container, &providers_before);
    assert!(
        residue.is_empty(),
        "the stopped oci main left runtime state behind:\n{}",
        describe(&residue)
    );

    // -- THE CONTAINER'S ANSWER ------------------------------------------------
    assert_eq!(doc["status"], "completed", "oci isolated run: {doc}");
    let parsed = &doc["outputs"]["probe"]["parsed"];
    for leg in [
        "committed",
        "exec",
        "symlink",
        "uncommitted_absent",
        "dirty_absent",
    ] {
        assert_eq!(
            parsed[leg], true,
            "the container's {leg} leg inside /work: {doc}"
        );
    }

    // -- RAW SQL: the durable head, the bound occurrence, no walk receipt -----
    let conn = raw(&oci_data);
    let (heads, head_artifact, base_len): (i64, Vec<u8>, i64) = conn
        .query_row(
            "SELECT count(*), (SELECT work_tree_artifact_id FROM execution_work_tree_heads), \
                    (SELECT length(base_commit) FROM execution_work_tree_heads) \
              FROM execution_work_tree_heads",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("the execution_work_tree_heads table reads");
    assert_eq!(heads, 1, "exactly one execution recorded a /work head");
    assert_eq!(base_len, 40, "the head's base is the jj commit's hex");
    let bound: Vec<u8> = conn
        .query_row("SELECT work_tree_artifact_id FROM occurrences", [], |row| {
            row.get(0)
        })
        .expect("exactly one occurrence bound a work tree");
    assert_eq!(
        bound, head_artifact,
        "the capsule bound the RECORDED head, not a walk's tree"
    );
    let trees: i64 = conn
        .query_row(
            "SELECT count(*) FROM artifacts WHERE kind = 'tree'",
            [],
            |row| row.get(0),
        )
        .expect("the artifacts table reads");
    assert_eq!(
        trees, 2,
        "the committed-base head plus the canonical empty /out+/tmp tree — no per-attempt \
         walk artifact"
    );
    println!(
        "WORK-HEAD-LIVE oci={} committed+exec+symlink inside /work, dirty checkout absent, \
         heads=1 bound=recorded trees=2",
        doc["id"]
    );
}

/// The paths a manifest's members carry, decoded raw — never by kata's readers.
fn manifest_member_paths(manifest: &[u8]) -> Vec<String> {
    let entries: serde_json::Value =
        serde_json::from_slice(manifest).expect("a tree manifest is JSON");
    entries["entries"]
        .as_array()
        .unwrap_or_else(|| panic!("the manifest has no entries array: {entries}"))
        .iter()
        .filter_map(|member| member["path"].as_str().map(str::to_owned))
        .collect()
}

/// The execution's root-head manifest, read the raw way: `execution_work_tree_heads`
/// `branch = ''` → `artifacts.object_id` → `cas.db`.
fn root_head_manifest_paths(data: &Path) -> Vec<String> {
    let conn = raw(data);
    let artifact: Vec<u8> = conn
        .query_row(
            "SELECT work_tree_artifact_id FROM execution_work_tree_heads WHERE branch = ''",
            [],
            |row| row.get(0),
        )
        .expect("the root head row");
    let object: Vec<u8> = conn
        .query_row(
            "SELECT object_id FROM artifacts WHERE artifact_id = ?1",
            [artifact.as_slice()],
            |row| row.get(0),
        )
        .expect("the head's artifact row");
    manifest_member_paths(&raw_cas_object(data, &object))
}

/// The root head row's `(head_seq, candidate_commit_id)`, raw off
/// `operational.db` — `head_seq` counts jj-leg applies onto the ROOT head, so a
/// fan-in that landed through ONE op reads `1`.
fn root_head_facts(data: &Path) -> (i64, String) {
    let conn = raw(data);
    conn.query_row(
        "SELECT head_seq, candidate_commit_id FROM execution_work_tree_heads WHERE branch = ''",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .expect("the root head row")
}

/// The isolated two-branch fan-in, live: each branch's capsule writes its own
/// file into `/work`, the join merges the two recorded deltas and lands them on
/// the root head through ONE apply — `head_seq` 1, one `#apply/` row naming the
/// join — and `git show <candidate>:<file>` reads BOTH writes off the head
/// commit, by git, never kata.
const FANIN_PACK: &str = "
def _branch(name):
    return stage(
        id = \"branch_\" + name,
        agent = \"shell\",
        sandbox = \"iso\",
        produces_files = [\"marker-\" + name + \".txt\"],
        prompt = \"\"\"printf 'branch-%s\\n' > /work/marker-%s.txt
printf '{\\\"branch\\\": \\\"%s\\\"}\\n'
\"\"\" % (name, name, name),
        outputs = { \"branch\": \"string\" },
    )

branch_a = _branch(\"a\")
branch_b = _branch(\"b\")
merge = stage(
    id = \"merge\",
    agent = \"shell\",
    sandbox = \"iso\",
    prompt = \"\"\"a=$(cat /work/marker-a.txt) && b=$(cat /work/marker-b.txt) && printf '{\\\"a\\\":\\\"%s\\\",\\\"b\\\":\\\"%s\\\"}\\n' \"$a\" \"$b\"
\"\"\",
    outputs = { \"a\": \"string\", \"b\": \"string\" },
)
join = parallel(branch_a, branch_b)
sequence(join, merge)
workflow(
    \"isolated-fanin\",
    root = [branch_a, branch_b],
    worktree_isolated = True,
    max_concurrency = 2,
    sandbox_profiles = {
        \"iso\": sandbox_profile(
            workspace = \"rw\",
            net = \"offline\",
        ),
    },
)
";

#[test]
#[ignore = "HOST-DEPENDENT like the differential (a certified rootless youki with its installed \
            AppArmor profile, a delegated user scope, the busybox closure realised, \
            `kata-provider-youki` built). Run alone, one test at a time: `cargo nextest run -p \
            kata -P live-smoke --test oci_main_live --run-ignored all`."]
fn an_isolated_fanin_lands_both_branches_in_one_apply_live() {
    let (fixture, root, repo) = oci_main_on_repo(FANIN_PACK);
    let (route, _unseal) = provision_provider(root.path());
    let data = root.path().join("data");
    let doc = {
        let main = Main::start(root.path(), &root.path().join("kata.toml"), true, &route);
        main.run(&root.path().join("pack.star"))
    };
    assert_eq!(doc["status"], "completed", "oci: {doc}");
    assert_eq!(
        doc["outputs"]["merge"]["parsed"],
        serde_json::json!({"a": "branch-a", "b": "branch-b"}),
        "the merge stage read both branches' writes: {doc}"
    );

    // ONE apply landed the union: the root head advanced exactly once, and the
    // only `#apply/` attempt at a jj leg is the join's.
    let conn = raw(&data);
    let (head_seq, candidate): (i64, String) = conn
        .query_row(
            "SELECT head_seq, candidate_commit_id FROM execution_work_tree_heads \
             WHERE branch = ''",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(head_seq, 1, "exactly one apply advanced the root head");
    let join_applies: i64 = conn
        .query_row(
            "SELECT count(*) FROM attempts WHERE stage_id = '#apply/__parallel_join_0'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(join_applies, 1, "the join's apply ran exactly once");
    // And BOTH branch writes are on the head's candidate — read by git.
    for (file, content) in [
        ("marker-a.txt", "branch-a\n"),
        ("marker-b.txt", "branch-b\n"),
    ] {
        let shown = hermetic_git_in(&repo)
            .args(["show", &format!("{candidate}:{file}")])
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&shown.stdout),
            content,
            "the fanned-in head carries {file}: {}",
            String::from_utf8_lossy(&shown.stderr)
        );
    }
    drop(fixture);
}

/// The conflict verdict, live: two branches write THE SAME path, the join
/// refuses `work_fanin_conflict` naming both, and the root head's sequence and
/// candidate are unmoved — a recorded verdict, not a partial merge.
const FANIN_CONFLICT_PACK: &str = "
def _branch(name):
    return stage(
        id = \"branch_\" + name,
        agent = \"shell\",
        sandbox = \"iso\",
        produces_files = [\"marker.txt\"],
        prompt = \"\"\"printf 'branch-%s\\n' > /work/marker.txt
printf '{\\\"branch\\\": \\\"%s\\\"}\\n'
\"\"\" % (name, name),
        outputs = { \"branch\": \"string\" },
    )

branch_a = _branch(\"a\")
branch_b = _branch(\"b\")
merge = stage(
    id = \"merge\",
    agent = \"shell\",
    sandbox = \"iso\",
    prompt = \"\"\"cat /work/marker.txt && printf '{\\\"read\\\":true}\\n'
\"\"\",
    outputs = { \"read\": \"bool\" },
)
join = parallel(branch_a, branch_b)
sequence(join, merge)
workflow(
    \"isolated-fanin-conflict\",
    root = [branch_a, branch_b],
    worktree_isolated = True,
    max_concurrency = 2,
    sandbox_profiles = {
        \"iso\": sandbox_profile(
            workspace = \"rw\",
            net = \"offline\",
        ),
    },
)
";

#[test]
#[ignore = "HOST-DEPENDENT like the differential (a certified rootless youki with its installed \
            AppArmor profile, a delegated user scope, the busybox closure realised, \
            `kata-provider-youki` built). Run alone, one test at a time: `cargo nextest run -p \
            kata -P live-smoke --test oci_main_live --run-ignored all`."]
fn an_isolated_fanin_conflict_fails_the_join_and_moves_no_head_live() {
    let (fixture, root, repo) = oci_main_on_repo(FANIN_CONFLICT_PACK);
    let (route, _unseal) = provision_provider(root.path());
    let data = root.path().join("data");
    let doc = {
        let main = Main::start(root.path(), &root.path().join("kata.toml"), true, &route);
        main.run(&root.path().join("pack.star"))
    };
    assert_eq!(
        doc["status"], "failed",
        "the contested join fails the run: {doc}"
    );
    // The operator surface carries the recorded reason —
    // `kata run show`'s `error` (the document above) names the token AND the
    // contested path, read off the `main_resolved` transition.
    let shown_error = doc["error"].as_str().unwrap_or("");
    assert!(
        shown_error.contains("work_fanin_conflict"),
        "run show names the fan-in verdict: {shown_error}"
    );
    assert!(
        shown_error.contains("marker.txt"),
        "run show names the contested path: {shown_error}"
    );
    // The same reason read raw from the durable record — the surface above and
    // this must agree, because the surface is the record projected.
    let conn = raw(&data);
    let reason: String = conn
        .query_row(
            "SELECT json_extract(t.payload_json, '$.reason') FROM transitions t \
             JOIN attempts a ON a.attempt_id = t.attempt_id \
             WHERE a.stage_id = '__parallel_join_0' AND t.resulting_state = 'failed'",
            [],
            |row| row.get(0),
        )
        .expect("the join's failed resolution names its reason");
    assert!(
        reason.contains("work_fanin_conflict"),
        "the join's recorded failure is the fan-in verdict: {reason}"
    );
    // No head moved: head_seq is still the admission baseline and the candidate
    // carries no `marker.txt` — read by git, failing with git's own error.
    let (head_seq, candidate) = root_head_facts(&data);
    assert_eq!(head_seq, 0, "the contested join advanced no head");
    let shown = hermetic_git_in(&repo)
        .args(["show", &format!("{candidate}:marker.txt")])
        .output()
        .unwrap();
    assert!(
        !shown.status.success(),
        "the candidate names no marker.txt: {}",
        String::from_utf8_lossy(&shown.stdout)
    );
    drop(fixture);
}

/// The contested fan-in under a real container, oci only: the two declared
/// workers write DIFFERENT bytes to the same `/work` path, the settle's merge
/// refuses `work_fanin_conflict`, the run fails naming it — and neither the
/// execution's recorded head nor the fixture's trunk moves.
const TOPOLOGY_CONFLICT_PACK: &str = r#"
parent = stage(
    id = "parent",
    agent = "shell",
    sandbox = "iso",
    produces_files = ["clash/marker.txt"],
    prompt = """role=$(tr '\\000' '\\n' < /proc/$$/cmdline 2>/dev/null | sed -n 's/^# Invocation role: //p' | head -n 1)
mkdir -p clash
if [ "$role" = "first_worker" ]; then printf 'first\\n' > clash/marker.txt; fi
if [ "$role" = "second_worker" ]; then printf 'second\\n' > clash/marker.txt; fi
printf '{"member":"%s"}\\n' "${role:-the_root}"
""",
    outputs = { "member": "string" },
    topology = topology(
        "root_with_parallel_workers",
        root = role("the_root", agent = "shell"),
        workers = [
            role("first_worker", agent = "shell"),
            role("second_worker", agent = "shell"),
        ],
        max_concurrency = 3,
    ),
)
workflow(
    "static-topology-conflict",
    root = [parent],
    worktree_isolated = True,
    sandbox_profiles = {
        "iso": sandbox_profile(
            workspace = "rw",
            net = "offline",
        ),
    },
)
"#;

#[test]
#[ignore = "HOST-DEPENDENT like the differential (a certified rootless youki with its installed \
            AppArmor profile, a delegated user scope, the busybox closure realised, \
            `kata-provider-youki` built). Run alone, one test at a time: `cargo nextest run -p \
            kata -P live-smoke --test oci_main_live --run-ignored all`."]
fn a_static_topology_same_path_writers_fail_work_fanin_conflict_live() {
    let (fixture, root, repo) = oci_main_on_repo(TOPOLOGY_CONFLICT_PACK);
    let trunk_before = {
        let out = hermetic_git_in(&repo)
            .args(["rev-parse", "main"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    let (route, _unseal) = provision_provider(root.path());
    let data = root.path().join("data");
    let doc = {
        let main = Main::start(root.path(), &root.path().join("kata.toml"), true, &route);
        main.run(&root.path().join("pack.star"))
    };
    assert_eq!(
        doc["status"], "failed",
        "the contested topology fails the run: {doc}"
    );
    let shown_error = doc["error"].as_str().unwrap_or("");
    assert!(
        shown_error.contains("work_fanin_conflict"),
        "run show names the fan-in verdict: {shown_error}"
    );
    // The same verdict read raw: a recorded `failed` transition names it —
    // the surface and the durable record agree.
    let conn = raw(&data);
    let reasons: i64 = conn
        .query_row(
            "SELECT count(*) FROM transitions t \
             WHERE json_extract(t.payload_json, '$.reason') LIKE '%work_fanin_conflict%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        reasons >= 1,
        "a recorded failed transition names work_fanin_conflict"
    );
    // NO HEAD MOVED, and the trunk the failed merge could never reach is
    // byte-identical — read by raw SQL and by git.
    let (head_seq, candidate) = root_head_facts(&data);
    assert_eq!(head_seq, 0, "the contested settle advanced no head");
    let shown = hermetic_git_in(&repo)
        .args(["show", &format!("{candidate}:clash/marker.txt")])
        .output()
        .unwrap();
    assert!(
        !shown.status.success(),
        "the candidate names no clash/marker.txt: {}",
        String::from_utf8_lossy(&shown.stdout)
    );
    let trunk_after = {
        let out = hermetic_git_in(&repo)
            .args(["rev-parse", "main"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    assert_eq!(
        trunk_before, trunk_after,
        "the contested merge never reached trunk"
    );
    println!(
        "TOPOLOGY-CONFLICT oci={} head_seq=0 trunk_unchanged",
        doc["id"]
    );
    drop(fixture);
}

/// LIVE — a shell stage whose structured output is invalid on
/// attempt 0 (`not json` against `outputs = {"ok": "bool"}`) but whose `/work`
/// delta — the `.attempt` marker it wrote — STANDS: the validation retry is a
/// second capsule at the stage seat's `child(1)`, sees the marker, and prints
/// the valid envelope. Raw: two `worker` attempts on `flaky`'s chain, the
/// retry's occurrence path the first's + `[1]`; the head manifest names
/// `.attempt`; `kata run show` (the operator's read) `parsed.ok = true`.
const VALIDATION_RETRY_PACK: &str = r#"
flaky = stage(
    id = "flaky",
    agent = "shell",
    sandbox = "iso",
    produces_files = ["state/.attempt"],
    prompt = """if [ -f state/.attempt ]; then printf '{\"ok\":true}\\n'; else mkdir -p state && printf x > state/.attempt && printf 'not json\\n'; fi
""",
    outputs = { "ok": "bool" },
)
workflow(
    "shell-validation-retry",
    root = [flaky],
    worktree_isolated = True,
    sandbox_profiles = {
        "iso": sandbox_profile(
            workspace = "rw",
            net = "offline",
        ),
    },
)
"#;

#[test]
#[ignore = "HOST-DEPENDENT like the differential (a certified rootless youki with its installed \
            AppArmor profile, a delegated user scope, the busybox closure realised, \
            `kata-provider-youki` built). Run alone, one test at a time: `cargo nextest run -p \
            kata -P live-smoke --test oci_main_live --run-ignored all`."]
fn a_shell_validation_retry_converges_in_a_real_container_live() {
    let (fixture, root, _repo) = oci_main_on_repo(VALIDATION_RETRY_PACK);
    let (route, _unseal) = provision_provider(root.path());
    let data = root.path().join("data");
    let doc = {
        let main = Main::start(root.path(), &root.path().join("kata.toml"), true, &route);
        main.run(&root.path().join("pack.star"))
    };
    assert_eq!(doc["status"], "completed", "oci: {doc}");
    assert_eq!(
        doc["outputs"]["flaky"]["parsed"]["ok"], true,
        "the retry's valid envelope is the stage's accepted output: {doc}"
    );

    // The chain, raw: two worker attempts on `flaky`, the retry's occurrence
    // path the first's + `[1]` — `OperationPath` decoded, never kata's answer.
    let conn = raw(&data);
    let attempts: i64 = conn
        .query_row(
            "SELECT count(*) FROM attempts WHERE stage_id = 'flaky' AND executor = 'worker'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(attempts, 2, "attempt 0 plus its one retry");
    let mut statement = conn
        .prepare(
            "SELECT o.operation_path FROM attempts a \
             JOIN occurrences o ON o.occurrence_id = a.occurrence_id \
             WHERE a.stage_id = 'flaky' ORDER BY a.attempt_ordinal",
        )
        .unwrap();
    let paths: Vec<Vec<u32>> = statement
        .query_map([], |row| {
            let bytes: Vec<u8> = row.get(0)?;
            Ok(
                kata_types::execution_contract::OperationPath::from_canonical_bytes(&bytes)
                    .expect("the attempt's operation path decodes")
                    .0,
            )
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(paths.len(), 2, "the chain is two seats: {paths:?}");
    let mut retry_seat = paths[0].clone();
    retry_seat.push(1);
    assert_eq!(
        paths[1], retry_seat,
        "the retry sits at the stage seat's child(1): {paths:?}"
    );
    // Attempt 0's /work delta stands: `state/.attempt` is on the landed head.
    let head_paths = root_head_manifest_paths(&data);
    assert!(
        head_paths.iter().any(|path| path == "state/.attempt"),
        "the invalid attempt's /work marker survived to the head: {head_paths:?}"
    );
    println!(
        "VALIDATION-RETRY oci={} attempts=2 retry_at={:?} head=state/.attempt",
        doc["id"], paths[1]
    );
    drop(fixture);
}

/// LIVE, both directions — `requires = ["git"]` judged against the
/// node's BOUND environment, on a real installed main.
///
/// POSITIVE: a node whose environment binds git's closure runs the stage
/// inside a real container, where `/work` is the disposable git view of the
/// execution's recorded history — `git log -1 --format=%H` prints the fixture
/// repo's `main` tip and `git status --short` is clean. The printed hash is
/// compared to `git rev-parse main` on the fixture, by git, never kata.
///
/// NEGATIVE: the same pack on a node whose environment lacks git is refused
/// `environment_requirement_unmet` at CHECK inside the booted main — and the
/// residue oracle proves no container ran.
const GIT_REQUIREMENT_PACK: &str = r#"
verdict = stage(
    id = "verdict",
    agent = "shell",
    sandbox = "gitview",
    prompt = """git log -1 --format=%H
git status --short
printf done
""",
)
workflow(
    "shell-git-history",
    root = [verdict],
    worktree_isolated = True,
    sandbox_profiles = {
        "gitview": sandbox_profile(
            workspace = "ro",
            net = "offline",
            requires = ["git"],
        ),
    },
)
"#;

#[test]
#[ignore = "HOST-DEPENDENT like the differential (a certified rootless youki with its installed \
            AppArmor profile, a delegated user scope, the busybox closure realised, the \
            git-minimal closure realised, `kata-provider-youki` built). Run alone, one test at a \
            time: `cargo nextest run -p kata -P live-smoke --test oci_main_live \
            --run-ignored all`."]
fn a_shell_stage_requiring_git_reads_the_runs_history_live() {
    // -- POSITIVE: the environment binds busybox + getent + the git closure.
    let fixture = tempfile::tempdir().expect("a fixture root");
    let repo = fixture.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    kata_test_utils::git::init_git_repo_at(&repo);
    let root = tempfile::tempdir().expect("an oci root");
    let config = write_config_with_programs(root.path(), "oci", &[GIT_MINIMAL]);
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        format!(
            "{text}\n[vcs]\njj_repo = \"{}\"\ntrunk = \"main\"\n",
            repo.display()
        ),
    )
    .unwrap();
    let pack = root.path().join("pack.star");
    std::fs::write(&pack, GIT_REQUIREMENT_PACK).unwrap();
    let trunk_sha = {
        let out = hermetic_git_in(&repo)
            .args(["rev-parse", "main"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    let (route, _unseal) = provision_provider(root.path());
    let doc = {
        let main = Main::start(root.path(), &config, true, &route);
        main.run(&pack)
    };
    assert_eq!(doc["status"], "completed", "oci: {doc}");
    // The capsule read the recorded history: stdout is the fixture trunk's tip
    // then `done` — a dirty `git status` would interleave lines between them.
    let content = doc["outputs"]["verdict"]["content"]
        .as_str()
        .unwrap_or_else(|| panic!("the verdict's content: {doc}"));
    assert_eq!(
        content,
        format!("{trunk_sha}\ndone"),
        "the disposable view's HEAD is the run's recorded base and its status is clean"
    );

    // -- NEGATIVE: the same pack, a node whose environment lacks git — the
    //    CHECK inside the booted main refuses admission BY NAME, and no
    //    container ever ran.
    let negative_root = tempfile::tempdir().expect("a negative oci root");
    let negative_config = write_config(negative_root.path(), "oci");
    let text = std::fs::read_to_string(&negative_config).unwrap();
    std::fs::write(
        &negative_config,
        format!(
            "{text}\n[vcs]\njj_repo = \"{}\"\ntrunk = \"main\"\n",
            repo.display()
        ),
    )
    .unwrap();
    let negative_pack = negative_root.path().join("pack.star");
    std::fs::write(&negative_pack, GIT_REQUIREMENT_PACK).unwrap();
    let (negative_route, _negative_unseal) = provision_provider(negative_root.path());
    let negative_data = negative_root.path().join("data");
    let worker_state = negative_data.join("oci-worker-state");
    let providers_before = cgroup_dirs("kata.provider.*");
    {
        let main = Main::start(
            negative_root.path(),
            &negative_config,
            true,
            &negative_route,
        );
        let submitted = kata()
            .args(["--api-url", &main.url, "run"])
            .arg(&negative_pack)
            .arg("--submit")
            .output()
            .expect("kata run --submit runs");
        let surface = format!(
            "{}{}",
            String::from_utf8_lossy(&submitted.stdout),
            String::from_utf8_lossy(&submitted.stderr)
        );
        assert!(
            !submitted.status.success(),
            "the unmet requirement is refused: {surface}"
        );
        assert!(
            surface.contains("environment_requirement_unmet"),
            "the refusal names itself: {surface}"
        );
    }
    let residue = runtime_residue(&worker_state, "", &providers_before);
    assert!(
        residue.is_empty(),
        "the refused admission ran no container:\n{}",
        describe(&residue)
    );
    println!(
        "REQUIRES-GIT oci={} trunk={} negative=environment_requirement_unmet",
        doc["id"],
        &trunk_sha[..8]
    );
    drop(fixture);
}

/// LIVE — a `dynamic_fanout` topology: the root (a shell stage) prints the
/// `child_invocation_requests` array naming two `owned_paths` children, each
/// request's own `prompt` a shell line writing its owned file — the same
/// payload shape the host-free `TWO_REQUESTS` scripts. `commit` + `promote`
/// land the merged fan-in on trunk; raw, the two children are `#child-`
/// occurrences with one accepted attempt each. Each child is a capsule on its
/// own `/work` branch merged at the settle.
const DYNAMIC_FANOUT_PACK: &str = r#"
fan = stage(
    id = "fan",
    agent = "shell",
    sandbox = "iso",
    produces_files = ["kids/child-a.txt", "kids/child-b.txt"],
    prompt = """printf '%s\\n' '{"child_invocation_requests":[{"role":"w","name":"a","prompt":"mkdir -p kids; printf from-a > kids/child-a.txt","owned_paths":["kids/child-a.txt"]},{"role":"w","name":"b","prompt":"mkdir -p kids; printf from-b > kids/child-b.txt","owned_paths":["kids/child-b.txt"]}]}'
""",
    topology = topology(
        "root_with_parallel_workers",
        root = role("planner", agent = "shell"),
        workers = [
            role("w", agent = "shell"),
        ],
        dynamic_fanout = True,
        mutation_policy = "owned_paths",
        max_concurrency = 3,
        fanout_limit = 3,
    ),
)
proof = stage(
    id = "proof",
    agent = "shell",
    sandbox = "iso",
    depends_on = [fan],
    prompt = """printf '{\"status\": \"passed\", \"criteria\": [{\"criterion_id\": \"ok\", \"status\": \"passed\", \"stage_name\": \"proof\", \"evidence\": [\"checked\"]}]}\\n'
""",
)
commit = stage(
    id = "commit",
    agent = "workspace_effect",
    op = "commit",
    depends_on = [proof],
)
promote = stage(
    id = "promote",
    agent = "workspace_effect",
    op = "promote",
    depends_on = [commit],
)
workflow(
    "dynamic-fanout",
    root = [fan],
    worktree_isolated = True,
    validation_criteria = [
        validation_criterion(
            "ok",
            description = "the deterministic proof stage passed",
            stage = "proof",
            required = True,
        ),
    ],
    sandbox_profiles = {
        "iso": sandbox_profile(
            workspace = "rw",
            net = "offline",
        ),
    },
)
"#;

/// The loop live cell, single-engine: `workflows/smoke/multistage-loop-smoke.star`
/// on ONE durable installed `oci` main, submitted through the normal client path.
/// The loop's body is a two-stage sub-DAG (`stage_a` → `stage_b`); the `controller`
/// gate emits `continue` twice then `promote`, so the whole body runs THREE
/// iterations and the expansion resolves `Approved` at iteration 2.
///
/// What it proves under the one engine:
///
/// * the run is `completed`, the outputs fold onto the three AUTHORED stage names —
///   each the last member's `capsule_result` — and `stage_a`'s marker is 2 (the
///   adopted iteration), not 0;
/// * the six markers (`markerA-{0,1,2}.txt`, `markerB-{0,1,2}.txt`) land on the
///   root work-tree head's manifest, read raw through `cas.db`;
/// * nine accepted `worker` attempts at member child coordinates, nine capsules,
///   nine `#apply/<stage>` applies, and ONE `{"expansion": …}` record at the `#op/`
///   coordinate carrying `Approved{iteration: 2}` and the verdict sequence
///   `continue, continue, promote` — decoded by the shared `ExpansionRecord`
///   reader, never kata's;
/// * no member container leaves runtime state with the main up or stopped.
#[test]
#[ignore = "HOST-DEPENDENT like the rest of this binary (a certified rootless youki with its \
            installed AppArmor profile, a delegated user scope, the busybox closure realised, \
            `kata-provider-youki` built). Run alone, one test at a time: `cargo nextest run -p \
            kata -P live-smoke --test oci_main_live --run-ignored all`."]
fn a_multistage_loop_runs_three_iterations_live() {
    let pack = repo_root().join("workflows/smoke/multistage-loop-smoke.star");

    // -- OCI ------------------------------------------------------------------
    let oci_root = tempfile::tempdir().expect("an oci root");
    let oci_config = write_config(oci_root.path(), "oci");
    let (route, _unseal) = provision_provider(oci_root.path());
    let oci_data = oci_root.path().join("data");
    let worker_state = oci_data.join("oci-worker-state");
    let providers_before = cgroup_dirs("kata.provider.*");
    let (oci_doc, containers) = {
        let main = Main::start(oci_root.path(), &oci_config, true, &route);
        let doc = main.run(&pack);
        let containers: Vec<String> = {
            let conn = raw(&oci_data);
            let mut statement = conn.prepare("SELECT capsule_id FROM capsules").unwrap();
            statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .unwrap()
                .map(|capsule| format!("kata-{}", hex::encode(capsule.unwrap())))
                .collect()
        };
        for container in &containers {
            let residue = runtime_residue(&worker_state, container, &providers_before);
            assert!(
                residue.is_empty(),
                "capsule {container} left runtime state behind while its main is up:\n{}",
                describe(&residue)
            );
        }
        (doc, containers)
    };
    for container in &containers {
        let residue = runtime_residue(&worker_state, container, &providers_before);
        assert!(
            residue.is_empty(),
            "the stopped oci main left runtime state behind for {container}:\n{}",
            describe(&residue)
        );
    }
    assert_eq!(oci_doc["status"], "completed", "oci: {oci_doc}");
    assert_eq!(containers.len(), 9, "nine member capsules ran");
    let oci_outputs = oci_doc["outputs"].as_object().unwrap();
    assert_eq!(
        oci_outputs
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        ["stage_a", "stage_b", "controller"]
            .into_iter()
            .collect::<BTreeSet<_>>(),
        "oci folds onto the authored stage names: {oci_doc}"
    );
    for authored in ["stage_a", "stage_b", "controller"] {
        assert_eq!(
            oci_doc["outputs"][authored]["kind"], "capsule_result",
            "{authored}'s output is the member's capsule result: {oci_doc}"
        );
    }
    assert_eq!(
        oci_doc["outputs"]["controller"]["parsed"]["decision"], "promote",
        "the gate's admitting verdict landed: {oci_doc}"
    );
    assert_eq!(
        oci_doc["outputs"]["stage_a"]["parsed"]["marker"], 2,
        "the authored name is the last member (iteration 2's marker): {oci_doc}"
    );

    // -- THE SIX MARKERS on the oci root head, raw ------------------------------
    let paths = root_head_manifest_paths(&oci_data);
    for marker in [
        "markerA-0.txt",
        "markerA-1.txt",
        "markerA-2.txt",
        "markerB-0.txt",
        "markerB-1.txt",
        "markerB-2.txt",
    ] {
        assert!(
            paths.iter().any(|path| path == marker),
            "the joined root-head manifest names {marker}: {paths:?}"
        );
    }

    // -- THE BOUND DECISION, raw: members, applies, the expansion record ---------
    let conn = raw(&oci_data);
    let members: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM occurrences o
               JOIN attempts a ON a.attempt_id = o.accepted_attempt_id
              WHERE a.executor = 'worker'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(members, 9, "nine accepted member capsules");
    let applies: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM attempts WHERE stage_id LIKE '#apply/%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(applies, 9, "each member's /work delta applied once");
    let (expansion_executor, payload): (String, Vec<u8>) = conn
        .query_row(
            "SELECT a.executor, t.payload_json FROM transitions t
               JOIN attempts a ON a.attempt_id = t.attempt_id
              WHERE a.stage_id LIKE '#op/%' AND t.resulting_state = 'completed'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the expansion's accepting transition exists");
    assert_eq!(
        expansion_executor, "main",
        "the bound decision is main-resolved"
    );
    let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    let record = kata_program::execution_program::expansion::ExpansionRecord::from_output(
        &payload["output"],
    )
    .expect("the accepted output is an expansion record");
    assert!(
        matches!(
            record.resolution,
            kata_program::execution_program::expansion::ExpansionResolution::Approved {
                iteration: 2
            }
        ),
        "the loop resolves Approved at iteration 2: {:?}",
        record.resolution
    );
    assert_eq!(record.members.len(), 9, "the record names every member");
    assert_eq!(
        record
            .verdicts
            .iter()
            .map(|verdict| verdict.verdict.as_str())
            .collect::<Vec<_>>(),
        ["continue", "continue", "promote"],
        "the gate's verdict sequence reads back"
    );
    println!(
        "LOOP oci={} members=9 applies={applies} markers={paths:?} runtime_residue=none",
        oci_doc["id"],
    );
}

/// The escalate live cell, single-engine: `workflows/smoke/loop-escalate-smoke.star`
/// on ONE durable installed `oci` main — two runs of the spent bound, one approved
/// through `kata run approve`, one rejected.
///
/// Under `oci` the gate IS the loop's own parked main attempt: `kata approvals`
/// lists it with `stage_name = "worker"`, the `#op/<path>` coordinate, the bound and
/// the classified count — no capsule and no effect bound. On approve the parked
/// `Exhausted{iterations: 2, Escalate}` record is adopted and the run completes
/// (`worker` folds the adopted iteration's envelope); on reject the expansion fails
/// with the operator's reason. Read raw: the `approval_decided` transition precedes
/// the `main_resolved` it authorized; each run mints four member capsules and four
/// `#apply` rows; the approved run's root head names both markers.
#[test]
#[ignore = "HOST-DEPENDENT like the rest of this binary (a certified rootless youki with its \
            installed AppArmor profile, a delegated user scope, the busybox closure realised, \
            `kata-provider-youki` built). Run alone, one test at a time: `cargo nextest run -p \
            kata -P live-smoke --test oci_main_live --run-ignored all`."]
fn an_exhausted_loop_escalates_to_the_operator_live() {
    let pack = repo_root().join("workflows/smoke/loop-escalate-smoke.star");

    // -- OCI: one run approved, one rejected ------------------------------------
    let oci_root = tempfile::tempdir().expect("an oci root");
    let oci_config = write_config(oci_root.path(), "oci");
    let (route, _unseal) = provision_provider(oci_root.path());
    let oci_data = oci_root.path().join("data");
    let worker_state = oci_data.join("oci-worker-state");
    let providers_before = cgroup_dirs("kata.provider.*");
    let (oci_doc, oci_gate, oci_rejected, containers) = {
        let main = Main::start(oci_root.path(), &oci_config, true, &route);
        let id = main.submit(&pack);
        let gate = main
            .next_gate(&id)
            .expect("the spent bound parks a gate under oci");
        main.decide(&gate, None);
        let doc = main.wait_terminal(&id);
        let rejected_id = main.submit(&pack);
        let rejected_gate = main
            .next_gate(&rejected_id)
            .expect("the second oci run parks too");
        main.decide(&rejected_gate, Some("operator holds the line"));
        let rejected = main.wait_terminal(&rejected_id);
        let containers: Vec<String> = {
            let conn = raw(&oci_data);
            let mut statement = conn.prepare("SELECT capsule_id FROM capsules").unwrap();
            statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .unwrap()
                .map(|capsule| format!("kata-{}", hex::encode(capsule.unwrap())))
                .collect()
        };
        (doc, gate, rejected, containers)
    };
    assert_eq!(
        containers.len(),
        8,
        "four member capsules per run — two iterations of worker + controller, \
         none for the parked `#op` gate: {containers:?}"
    );
    for container in &containers {
        let residue = runtime_residue(&worker_state, container, &providers_before);
        assert!(
            residue.is_empty(),
            "the stopped oci main left runtime state behind for {container}:\n{}",
            describe(&residue)
        );
    }

    // The oci gate IS the loop's own parked main attempt: the authored stage,
    // the `#op/<path>` coordinate, the bound and the classified count.
    let expansion = &oci_gate["expansion"];
    assert_eq!(oci_gate["stage_name"], "worker", "{oci_gate}");
    assert!(
        expansion["path"]
            .as_str()
            .unwrap_or_default()
            .starts_with("#op/"),
        "the gate names the expansion's own coordinate: {oci_gate}"
    );
    assert_eq!(expansion["stage"], "worker", "{oci_gate}");
    assert_eq!(
        (
            expansion["maximum"].as_u64(),
            expansion["iterations"].as_u64()
        ),
        (Some(2), Some(2)),
        "the bound spent after both iterations classified: {oci_gate}"
    );
    assert!(
        oci_gate["capsule"].is_null() && oci_gate["workspace_effect"].is_null(),
        "an expansion gate binds no capsule and no effect: {oci_gate}"
    );

    assert_eq!(oci_doc["status"], "completed", "approved run: {oci_doc}");
    assert_eq!(
        oci_doc["outputs"]["controller"]["parsed"]["decision"], "continue",
        "the gate never approved on its own: {oci_doc}"
    );
    // `worker` folds the ADOPTED iteration's envelope: marker 1, the last
    // iteration's member, projected onto the authored name.
    assert_eq!(
        oci_doc["outputs"]["worker"]["parsed"]["marker"], 1,
        "the authored name is the adopted iteration: {oci_doc}"
    );
    let oci_keys: BTreeSet<String> = oci_doc["outputs"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        oci_keys,
        ["worker", "controller"]
            .into_iter()
            .map(String::from)
            .collect::<BTreeSet<_>>(),
        "oci folds onto the authored names: {oci_doc}"
    );
    assert_eq!(
        oci_rejected["status"], "failed",
        "the rejected run fails: {oci_rejected}"
    );

    // -- RAW SQLITE: the decision, the record, the members, the head -------------
    let conn = raw(&oci_data);
    for (id, approved) in [
        (oci_doc["id"].as_str().unwrap(), true),
        (oci_rejected["id"].as_str().unwrap(), false),
    ] {
        let execution = ulid::Ulid::from_string(id).unwrap().to_bytes().to_vec();
        let (verdict, principal, decision_seq): (String, String, i64) = conn
            .query_row(
                "SELECT json_extract(t.payload_json, '$.decision'), \
                        json_extract(t.payload_json, '$.principal.kind'), t.seq \
                   FROM transitions t JOIN attempts a ON a.attempt_id = t.attempt_id \
                  WHERE a.execution_id = ?1 AND a.stage_id LIKE '#op/%' \
                    AND t.kind = 'approval_decided'",
                [execution.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("the expansion gate's decision is durable");
        assert_eq!(
            (verdict.as_str(), principal.as_str()),
            (
                if approved { "approve" } else { "reject" },
                "unauthenticated_loopback"
            ),
            "{id}: the operator's verdict is what the door recorded"
        );
        let (state, payload, resolved_seq): (String, Vec<u8>, i64) = conn
            .query_row(
                "SELECT t.resulting_state, t.payload_json, t.seq FROM transitions t \
                   JOIN attempts a ON a.attempt_id = t.attempt_id \
                  WHERE a.execution_id = ?1 AND a.stage_id LIKE '#op/%' \
                    AND t.kind = 'main_resolved'",
                [execution.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("the `#op` attempt resolved");
        assert!(
            resolved_seq > decision_seq,
            "{id}: the decision ({decision_seq}) precedes the resolution it authorized \
             ({resolved_seq})"
        );
        if approved {
            assert_eq!(state, "completed", "{id}: the approve adopted the record");
            let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
            let record = kata_program::execution_program::expansion::ExpansionRecord::from_output(
                &payload["output"],
            )
            .expect("the adopted output is an expansion record");
            assert!(
                matches!(
                    record.resolution,
                    kata_program::execution_program::expansion::ExpansionResolution::Exhausted {
                        iterations: 2,
                        on_max:
                            kata_program::execution_program::expansion::ExpansionOnMax::Escalate,
                    }
                ),
                "{id}: the adopted record is the park's own Exhausted{{Escalate}}: {:?}",
                record.resolution
            );
            assert_eq!(record.verdicts.len(), 2, "{id}: both iterations classified");
        } else {
            assert_eq!(state, "failed", "{id}: the reject failed the expansion");
            let reason = String::from_utf8_lossy(&payload).into_owned();
            assert!(
                reason.contains("rejected: operator holds the line"),
                "{id}: the failure names the operator's reason: {reason}"
            );
        }
        for (sql, want, what) in [
            (
                "SELECT count(*) FROM attempts a JOIN occurrences o \
                   ON o.accepted_attempt_id = a.attempt_id \
                  WHERE a.execution_id = ?1 AND a.executor = 'worker'",
                4,
                "member capsules",
            ),
            (
                "SELECT count(*) FROM attempts WHERE execution_id = ?1 \
                   AND stage_id LIKE '#apply/%'",
                4,
                "#apply rows",
            ),
        ] {
            let got: i64 = conn
                .query_row(sql, [execution.as_slice()], |row| row.get(0))
                .unwrap();
            assert_eq!(got, want, "{id}: {what}");
        }
    }

    // The approved run's root head names both markers — the durable /work tree
    // the member applies built.
    let head_artifact: Vec<u8> = conn
        .query_row(
            "SELECT work_tree_artifact_id FROM execution_work_tree_heads \
              WHERE execution_id = ?1 AND branch = ''",
            [ulid::Ulid::from_string(oci_doc["id"].as_str().unwrap())
                .unwrap()
                .to_bytes()
                .as_slice()],
            |row| row.get(0),
        )
        .expect("the approved run's head row");
    let head_object: Vec<u8> = conn
        .query_row(
            "SELECT object_id FROM artifacts WHERE artifact_id = ?1",
            [head_artifact.as_slice()],
            |row| row.get(0),
        )
        .expect("the head's artifact row");
    let paths = manifest_member_paths(&raw_cas_object(&oci_data, &head_object));
    for marker in ["marker-0.txt", "marker-1.txt"] {
        assert!(
            paths.iter().any(|path| path == marker),
            "the approved run's head names {marker}: {paths:?}"
        );
    }
    println!(
        "ESCALATE oci={} rejected={} members=4 applies=4 markers=2 runtime_residue=none",
        oci_doc["id"], oci_rejected["id"],
    );
}

/// The dynamic fanout, single-engine: the root's `child_invocation_requests` array
/// mints two children, each a capsule on its own `/work` branch merged at the
/// settle — asserted off the fixture's trunk with `git` and off the durable census
/// raw: exactly two `#child-` occurrences (`fan#child-w-a`, `fan#child-w-b`), each
/// with its one accepted attempt.
#[test]
#[ignore = "HOST-DEPENDENT like the rest of this binary (a certified rootless youki with its \
            installed AppArmor profile, a delegated user scope, the busybox closure realised, \
            `kata-provider-youki` built). Run alone, one test at a time: `cargo nextest run -p \
            kata -P live-smoke --test oci_main_live --run-ignored all`."]
fn a_dynamic_fanout_runs_its_requested_children_live() {
    let (fixture, root, repo) = oci_main_on_repo(DYNAMIC_FANOUT_PACK);
    let (route, _unseal) = provision_provider(root.path());
    let data = root.path().join("data");
    let oci_doc = {
        let main = Main::start(root.path(), &root.path().join("kata.toml"), true, &route);
        main.run(&root.path().join("pack.star"))
    };
    assert_eq!(oci_doc["status"], "completed", "oci: {oci_doc}");

    // The landed truth, by git: both owned files on the trunk.
    for (file, content) in [
        ("kids/child-a.txt", "from-a"),
        ("kids/child-b.txt", "from-b"),
    ] {
        let shown = hermetic_git_in(&repo)
            .args(["show", &format!("main:{file}")])
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&shown.stdout),
            content,
            "trunk's {file} carries the child's write: {}",
            String::from_utf8_lossy(&shown.stderr)
        );
    }

    // The durable census, raw: exactly two `#child-` occurrences, each with its
    // one accepted attempt.
    let conn = raw(&data);
    let mut statement = conn
        .prepare(
            "SELECT a.stage_id, o.accepted_attempt_id IS NOT NULL FROM attempts a \
             JOIN occurrences o ON o.occurrence_id = a.occurrence_id \
             WHERE a.stage_id LIKE '%#child-%' ORDER BY a.stage_id",
        )
        .unwrap();
    let children: Vec<(String, bool)> = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        children,
        [
            ("fan#child-w-a".to_owned(), true),
            ("fan#child-w-b".to_owned(), true),
        ],
        "two dynamic children, each accepted exactly once: {children:?}"
    );
    println!(
        "DYNAMIC-FANOUT oci={} children={:?}",
        oci_doc["id"],
        children
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
    );
    drop(fixture);
}

/// `count(sql)` over one execution's rows, read raw.
fn count(conn: &rusqlite::Connection, sql: &str, execution: &str) -> i64 {
    conn.query_row(
        sql,
        [ulid::Ulid::from_string(execution)
            .expect("a ulid")
            .to_bytes()
            .as_slice()],
        |row| row.get(0),
    )
    .unwrap_or_else(|error| panic!("{sql}: {error}"))
}

/// `(last transition state, its reason, completed transitions, attempts)` of `stage`, raw.
fn raw_stage_end(data: &Path, stage: &str) -> (Option<String>, String, i64, i64) {
    let conn = raw(data);
    let (last_state, last_reason) = conn
        .query_row(
            "SELECT t.resulting_state, coalesce(json_extract(t.payload_json, '$.reason'), '')
               FROM transitions t JOIN attempts a ON a.attempt_id = t.attempt_id
              WHERE a.stage_id = ?1 ORDER BY t.seq DESC LIMIT 1",
            [stage],
            |row| Ok((Some(row.get::<_, String>(0)?), row.get::<_, String>(1)?)),
        )
        .unwrap_or((None, String::new()));
    let (completed, attempts): (i64, i64) = conn
        .query_row(
            "SELECT (SELECT count(*) FROM transitions t JOIN attempts a
                        ON a.attempt_id = t.attempt_id
                      WHERE a.stage_id = ?1 AND t.resulting_state = 'completed'),
                    (SELECT count(*) FROM attempts WHERE stage_id = ?1)",
            [stage],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    (last_state, last_reason, completed, attempts)
}

/// The shipped `durable-wait-signal` pack, by path.
const WAIT_SIGNAL_PACK: &str = "workflows/examples/durable-wait-signal.star";
/// Its blocking request's main attempt coordinate.
const INPUT_WAIT_STAGE: &str = "#op/1";

/// The `workflows/smoke` rig `subworkflow-parent-smoke` (its child `subworkflow-child-smoke`), by path.
const SUBWORKFLOW_PACK: &str = "workflows/smoke/subworkflow-parent-smoke.star";

/// The exit-status fixture: `gate` authors `exit_policy = "content"` and exits 3 (its
/// content is its verdict); `boom` exits 3 under the default `zero_success` policy;
/// `after` depends on `boom`.
const EXIT_STATUS_PACK: &str = "gate = stage(id = \"gate\", agent = \"shell\", \
     run = \"echo gate-said; exit 3\", exit_policy = \"content\")\n\
     boom = stage(id = \"boom\", agent = \"shell\", \
     run = \"echo boom-said; echo boom-err >&2; exit 3\", depends_on = [gate])\n\
     after = stage(id = \"after\", agent = \"shell\", run = \"true\", depends_on = [boom])\n\
     workflow(\"exit-status\", root = [gate])\n";

/// The capture-bound fixture: `full` prints exactly the authored `output_bytes`
/// bound; `big` prints one byte past it; `after` depends on `big`.
const CAPTURE_PACK: &str = "full = stage(id = \"full\", agent = \"shell\", \
     run = \"head -c 1048576 </dev/zero\", output_bytes = 1048576)\n\
     big = stage(id = \"big\", agent = \"shell\", run = \"head -c 1048577 </dev/zero\", \
     output_bytes = 1048576, depends_on = [full])\n\
     after = stage(id = \"after\", agent = \"shell\", run = \"true\", depends_on = [big])\n\
     workflow(\"capture-bound\", root = [full])\n";

/// The two `branch()` packs (the example and the rig), with each one's condition, verdict
/// field, taken arm and NOT-taken arm.
const BRANCH_PACKS: &[(&str, &str, &str, &str, &str)] = &[
    (
        "workflows/examples/branch-routing.star",
        "classify",
        "verdict",
        "ship",
        "hold",
    ),
    (
        "workflows/smoke/branch-walkaway-smoke.star",
        "decide",
        "choice",
        "first",
        "second",
    ),
];

impl Main {
    /// The request row `kata steer human-requests` lists for `id`, waiting until it
    /// carries `status` — `None`-free by assertion.
    fn wait_for_request_row(&self, id: &str, status: &str) -> serde_json::Value {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let listed = kata()
                .args([
                    "--api-url",
                    &self.url,
                    "steer",
                    "human-requests",
                    "--execution-id",
                    id,
                ])
                .output()
                .expect("kata steer human-requests runs");
            assert!(
                listed.status.success(),
                "{}",
                String::from_utf8_lossy(&listed.stderr)
            );
            if let Some(row) = String::from_utf8_lossy(&listed.stdout)
                .lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .find(|row| row["request_id"] == "proceed_q" && row["request_status"] == status)
            {
                return row;
            }
            assert!(
                Instant::now() < deadline,
                "execution {id}'s proceed_q never listed `{status}`; the main's log is {}",
                self.log.display()
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// `kata steer answer-human-request <id> proceed_q <answer>`.
    fn answer(&self, id: &str, answer: &str) -> std::process::Output {
        kata()
            .args([
                "--api-url",
                &self.url,
                "steer",
                "answer-human-request",
                id,
                "proceed_q",
                answer,
            ])
            .output()
            .expect("kata steer answer-human-request runs")
    }
}

/// `branch()` on ONE durable installed `oci` main, both branch packs through the
/// normal client path.
///
/// Off the main's own `kata run show`: each run is `completed`; the condition and the
/// taken arm's `parsed` outputs are the pack's own; the not-taken stage has no output
/// and — read raw — no attempt at all. The decision is ONE accepted `Select` occurrence
/// at `#op/<path>` (`executor = 'main'`, no capsule) whose accepted verdict is the key of
/// the condition's `parsed.<field>`, accepted no earlier than its condition, and which
/// `kata run show` serves as `routing`. No capsule leaves runtime state once the main is
/// stopped.
#[test]
#[ignore = "HOST-DEPENDENT like the rest of this binary (a certified rootless youki with its \
            installed AppArmor profile, a delegated user scope, the busybox closure realised, \
            `kata-provider-youki` built). Run alone, one test at a time: `cargo nextest run -p \
            kata -P live-smoke --test oci_main_live --run-ignored all`."]
fn a_branch_routing_decides_once_and_runs_only_the_taken_arm_live() {
    let oci_root = tempfile::tempdir().expect("an oci root");
    let oci_config = write_config(oci_root.path(), "oci");
    let (route, _unseal) = provision_provider(oci_root.path());
    let oci_data = oci_root.path().join("data");
    let worker_state = oci_data.join("oci-worker-state");
    let providers_before = cgroup_dirs("kata.provider.*");
    let oci_docs: Vec<serde_json::Value> = {
        let main = Main::start(oci_root.path(), &oci_config, true, &route);
        BRANCH_PACKS
            .iter()
            .map(|(pack, ..)| main.run(Path::new(pack)))
            .collect()
    };
    let oci_conn = raw(&oci_data);

    for ((pack, condition, field, taken, not_taken), oci) in BRANCH_PACKS.iter().zip(&oci_docs) {
        assert_eq!(oci["status"], "completed", "{pack}: {oci}");
        for stage in [condition, taken] {
            assert!(
                !oci["outputs"][stage].is_null(),
                "{pack}: {stage} has an output: {oci}"
            );
        }
        let verdict = oci["outputs"][condition]["parsed"][field]
            .as_object()
            .and_then(|variant| variant.keys().next().cloned())
            .unwrap_or_else(|| panic!("{pack}: the condition's verdict is a variant: {oci}"));
        assert_eq!(verdict, *taken, "{pack}: the pack's fixed verdict");

        // -- The not-taken stage NEVER RAN, read raw --------------------------------------
        let oci_id = oci["id"].as_str().unwrap();
        let not_taken_attempts: i64 = oci_conn
            .query_row(
                "SELECT count(*) FROM attempts WHERE execution_id = ?1 AND stage_id = ?2",
                rusqlite::params![
                    ulid::Ulid::from_string(oci_id)
                        .unwrap()
                        .to_bytes()
                        .as_slice(),
                    not_taken
                ],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(not_taken_attempts, 0, "{pack}: {not_taken} has no attempt");
        assert_eq!(
            count(
                &oci_conn,
                "SELECT count(*) FROM transitions WHERE execution_id = ?1 \
                 AND scope = 'stage' \
                 AND json_extract(CAST(payload_json AS TEXT), '$.stage_name') LIKE '%#branch-skip'",
                oci_id
            ),
            0,
            "{pack}: oci writes no #branch-skip row"
        );

        // -- ONE accepted Select occurrence, by a main attempt, with no capsule ------------
        let (selects, accepted_selects, select_capsules): (i64, i64, i64) = oci_conn
            .query_row(
                "SELECT count(*), count(o.accepted_attempt_id), \
                        (SELECT count(*) FROM occurrences o2 \
                          JOIN attempts a2 ON a2.occurrence_id = o2.occurrence_id \
                         WHERE o2.execution_id = ?1 AND a2.executor = 'main' \
                           AND o2.capsule_id IS NOT NULL) \
                   FROM occurrences o JOIN attempts a ON a.attempt_id = o.accepted_attempt_id \
                  WHERE o.execution_id = ?1 AND a.executor = 'main' \
                    AND a.stage_id LIKE '#op/%'",
                [ulid::Ulid::from_string(oci_id)
                    .unwrap()
                    .to_bytes()
                    .as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("the Select occurrence reads");
        assert_eq!(
            (selects, accepted_selects, select_capsules),
            (1, 1, 0),
            "{pack}: ONE accepted Select occurrence, by a main attempt, with no capsule"
        );
        assert_eq!(
            count(
                &oci_conn,
                "SELECT count(*) FROM occurrences o WHERE o.execution_id = ?1 \
                 AND EXISTS (SELECT 1 FROM attempts a \
                   WHERE a.occurrence_id = o.occurrence_id \
                   AND a.stage_id NOT LIKE '#apply/%')",
                oci_id
            ),
            3,
            "{pack}: the condition's, the taken arm's and the Select's occurrences — none \
             for the not-taken arm (the `#apply/` bookkeeping rows are the head's, not stages')"
        );
        let (select_verdict, select_taken, select_at, condition_at): (String, String, i64, i64) =
            oci_conn
                .query_row(
                    "SELECT json_extract(CAST(t.payload_json AS TEXT), '$.output.select.verdict'), \
                            json_extract(CAST(t.payload_json AS TEXT), '$.output.select.taken'), \
                            o.accepted_at_ms, \
                            (SELECT oc.accepted_at_ms FROM occurrences oc \
                               JOIN attempts ac ON ac.attempt_id = oc.accepted_attempt_id \
                              WHERE oc.execution_id = ?1 AND ac.stage_id = ?2) \
                       FROM occurrences o JOIN attempts a ON a.attempt_id = o.accepted_attempt_id \
                       JOIN transitions t ON t.attempt_id = a.attempt_id \
                      WHERE o.execution_id = ?1 AND a.stage_id LIKE '#op/%' \
                        AND t.resulting_state = 'completed'",
                    rusqlite::params![
                        ulid::Ulid::from_string(oci_id)
                            .unwrap()
                            .to_bytes()
                            .as_slice(),
                        condition
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .expect("the accepting transition carries the Select record");
        assert_eq!(
            (select_verdict.as_str(), select_taken.as_str()),
            (verdict.as_str(), *taken),
            "{pack}: the accepted verdict is the key of parsed.{field}"
        );
        assert!(
            select_at >= condition_at,
            "{pack}: the Select ({select_at}) is accepted no earlier than its condition \
             ({condition_at})"
        );
        assert_eq!(
            oci["routing"],
            serde_json::json!([{
                "condition": condition,
                "taken": taken,
                "not_taken": [not_taken],
            }]),
            "{pack}: `kata run show` serves the decision"
        );
        println!("BRANCH {pack} oci={oci_id} verdict={verdict} select=1");
    }

    // -- Runtime residue: none, for every capsule, with the oci main stopped --------------
    let mut statement = oci_conn
        .prepare("SELECT capsule_id FROM capsules")
        .expect("capsules read");
    let containers: Vec<String> = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .expect("capsules read")
        .map(|capsule| format!("kata-{}", hex::encode(capsule.unwrap())))
        .collect();
    for container in &containers {
        let residue = runtime_residue(&worker_state, container, &providers_before);
        assert!(
            residue.is_empty(),
            "{container} left runtime state:\n{}",
            describe(&residue)
        );
    }
}

/// A BLOCKING HUMAN REQUEST ANSWERED, on one `oci` main: the shipped
/// `durable-wait-signal` pack answered through `kata steer answer-human-request`.
///
/// * While held, `kata steer human-requests` lists the request `awaiting_input` and,
///   raw, `decide` has no attempt and no capsule exists; after the answer it lists
///   `answered`.
/// * The request is one accepted `executor = 'main'` attempt at `#op/1` whose output
///   records `unauthenticated_loopback` (the main runs loopback with auth disabled);
///   `decide`'s first transition follows it; the ONE capsule's argv, read out of
///   `cas.db`, carries the answer; a second answer after completion is refused 409
///   `main_resolution_execution_terminal`.
/// * `kata run show` serves `completed` with `decide`'s parsed output the answer
///   `ship-it` from `operator`.
#[test]
#[ignore = "HOST-DEPENDENT like the rest of this binary (a certified rootless youki with its \
            installed AppArmor profile, a delegated user scope, the busybox closure realised, \
            `kata-provider-youki` built). Run alone, one test at a time: `cargo nextest run -p \
            kata -P live-smoke --test oci_main_live --run-ignored all`."]
fn a_blocking_human_request_resumes_on_the_answer_live() {
    let oci_root = tempfile::tempdir().expect("an oci root");
    let oci_config = write_config(oci_root.path(), "oci");
    let (route, _unseal) = provision_provider(oci_root.path());
    let oci_data = oci_root.path().join("data");
    let (oci_answered, answered_id, waiting_row, second) = {
        let main = Main::start(oci_root.path(), &oci_config, true, &route);
        let id = main.submit(Path::new(WAIT_SIGNAL_PACK));
        let waiting_row = main.wait_for_request_row(&id, "awaiting_input");
        assert_eq!(
            count(
                &raw(&oci_data),
                "SELECT count(*) FROM attempts WHERE execution_id = ?1 AND stage_id = 'decide'",
                &id
            ),
            0,
            "nothing of decide exists while it waits"
        );
        let capsules: i64 = raw(&oci_data)
            .query_row("SELECT count(*) FROM capsules", [], |row| row.get(0))
            .unwrap();
        assert_eq!(capsules, 0, "no capsule while the request waits");
        let answered = main.answer(&id, "ship-it");
        assert!(answered.status.success(), "{answered:?}");
        let answered_doc = main.wait_terminal(&id);
        main.wait_for_request_row(&id, "answered");
        let second = main.answer(&id, "changed-my-mind");
        (answered_doc, id, waiting_row, second)
    };
    assert_eq!(oci_answered["status"], "completed", "{oci_answered}");
    assert_eq!(
        oci_answered["outputs"]["decide"]["parsed"]["answer"],
        "ship-it"
    );
    assert_eq!(
        oci_answered["outputs"]["decide"]["parsed"]["source"],
        "operator"
    );
    assert!(!second.status.success(), "a second answer is refused");
    let refusal = format!(
        "{}{}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(
        refusal.contains("status=409") && refusal.contains("main_resolution_execution_terminal"),
        "{refusal}"
    );
    // -- RAW ---------------------------------------------------------------------
    let conn = raw(&oci_data);
    let (executor, output, accept_seq): (String, serde_json::Value, i64) = conn
        .query_row(
            "SELECT a.executor, json_extract(t.payload_json, '$.output'), t.seq
               FROM attempts a
               JOIN occurrences o ON o.accepted_attempt_id = a.attempt_id
               JOIN transitions t ON t.attempt_id = a.attempt_id AND t.resulting_state = 'completed'
              WHERE a.stage_id = ?1 AND a.execution_id = ?2",
            rusqlite::params![
                INPUT_WAIT_STAGE,
                ulid::Ulid::from_string(&answered_id)
                    .unwrap()
                    .to_bytes()
                    .as_slice()
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    serde_json::from_str(&row.get::<_, String>(1)?).unwrap(),
                    row.get(2)?,
                ))
            },
        )
        .expect("the answered wait is one accepted main attempt");
    assert_eq!(executor, "main");
    assert_eq!(output["answer"], "ship-it");
    assert_eq!(output["answered_by"]["kind"], "unauthenticated_loopback");
    let execution = ulid::Ulid::from_string(&answered_id).unwrap().to_bytes();
    let (decide_first, capsule_object): (i64, Vec<u8>) = conn
        .query_row(
            "SELECT (SELECT min(t.seq) FROM transitions t JOIN attempts a
                        ON a.attempt_id = t.attempt_id
                      WHERE a.execution_id = ?1 AND a.stage_id = 'decide'),
                    (SELECT c.capsule_object_id FROM capsules c JOIN occurrences o
                        ON o.occurrence_id = c.occurrence_id WHERE o.execution_id = ?1)",
            [execution.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("decide ran one capsule");
    assert!(decide_first > accept_seq, "decide followed the acceptance");
    let capsule: serde_json::Value =
        serde_json::from_slice(&raw_cas_object(&oci_data, &capsule_object))
            .expect("the capsule object decodes");
    let argv = capsule["process"]["argv"].to_string();
    assert!(
        argv.contains("'ship-it'"),
        "the capsule's argv carries the answer: {argv}"
    );
    println!(
        "INPUT-WAIT oci={} waiting_row_status={} accepted={output} \
         second_answer_refused=409",
        oci_answered["id"], waiting_row["request_status"],
    );
}

/// `workflows/smoke/subworkflow-parent-smoke.star` (its child `subworkflow-child-smoke`)
/// on ONE durable `oci` main: `sub` is ONE accepted `executor = 'main'` attempt with no
/// capsule whose `child_execution_id` names the node's one other execution — `completed`,
/// running the program the parent's CHECK bound — the parent's `dynamic_child_spawned`
/// record names it, `after`'s relayed output is the child's own, and exactly four
/// capsules ran (before, after, and the child's two), none leaving runtime state.
#[test]
#[ignore = "HOST-DEPENDENT like the rest of this binary (a certified rootless youki with its \
            installed AppArmor profile, a delegated user scope, the busybox closure realised, \
            `kata-provider-youki` built). Run alone, one test at a time: `cargo nextest run -p \
            kata -P live-smoke --test oci_main_live --run-ignored all`."]
fn the_subworkflow_smoke_runs_one_linked_child_live() {
    let oci_root = tempfile::tempdir().expect("an oci root");
    let oci_config = write_config(oci_root.path(), "oci");
    let (route, _unseal) = provision_provider(oci_root.path());
    let oci_data = oci_root.path().join("data");
    let worker_state = oci_data.join("oci-worker-state");
    let providers_before = cgroup_dirs("kata.provider.*");
    let (oci_doc, containers) = {
        let main = Main::start(oci_root.path(), &oci_config, true, &route);
        let doc = main.run(Path::new(SUBWORKFLOW_PACK));
        let containers: Vec<String> = {
            let conn = raw(&oci_data);
            let mut statement = conn.prepare("SELECT capsule_id FROM capsules").unwrap();
            statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .unwrap()
                .map(|capsule| format!("kata-{}", hex::encode(capsule.unwrap())))
                .collect()
        };
        for container in &containers {
            let residue = runtime_residue(&worker_state, container, &providers_before);
            assert!(
                residue.is_empty(),
                "{container} (main up):\n{}",
                describe(&residue)
            );
        }
        (doc, containers)
    };
    for container in &containers {
        let residue = runtime_residue(&worker_state, container, &providers_before);
        assert!(
            residue.is_empty(),
            "{container} (main stopped):\n{}",
            describe(&residue)
        );
    }
    assert_eq!(oci_doc["status"], "completed", "oci: {oci_doc}");
    for stage in ["before", "after"] {
        assert!(
            !oci_doc["outputs"][stage].is_null(),
            "{stage}: the parent's stages carry outputs: {oci_doc}"
        );
    }
    assert_eq!(
        oci_doc["outputs"]["sub"]["outputs"]["second"]["parsed"],
        serde_json::json!({"echoed": "child-value-echoed"}),
        "the child's output, as the parent's envelope carries it"
    );
    assert_eq!(
        oci_doc["outputs"]["after"]["parsed"]["relayed"],
        "child-value-echoed"
    );
    // -- RAW: one main attempt, one linked child ------------------------------------
    let conn = raw(&oci_data);
    let parent = oci_doc["id"].as_str().expect("an id").to_owned();
    let (executor, child, capsules): (String, Vec<u8>, i64) = conn
        .query_row(
            "SELECT a.executor, a.child_execution_id,
                    (SELECT count(*) FROM capsules c WHERE c.occurrence_id = a.occurrence_id)
               FROM occurrences o JOIN attempts a ON a.attempt_id = o.accepted_attempt_id
              WHERE a.stage_id = 'sub'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("sub's occurrence is accepted");
    assert_eq!((executor.as_str(), capsules), ("main", 0));
    let child_id = ulid::Ulid::from_bytes(child.clone().try_into().unwrap()).to_string();
    assert_eq!(
        oci_doc["outputs"]["sub"]["child_execution_id"], child_id,
        "the accepted envelope names the linked child"
    );
    let executions: Vec<(Vec<u8>, String)> = {
        let mut statement = conn
            .prepare("SELECT execution_id, state FROM execution_lifecycle")
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert_eq!(
        executions.len(),
        2,
        "the parent and ONE child: {executions:?}"
    );
    assert!(
        executions
            .iter()
            .any(|(id, state)| *id == child && state == "completed"),
        "the child is its own completed execution"
    );
    let spawned: String = conn
        .query_row(
            "SELECT CAST(payload_json AS TEXT) FROM transitions WHERE kind = 'dynamic_child_spawned'",
            [],
            |row| row.get(0),
        )
        .expect("one bound record");
    assert_eq!(spawned, child_id, "the parent's bound names the child");
    let child_program: String = conn
        .query_row(
            "SELECT lower(hex(program_hash)) FROM programs WHERE execution_id = ?1",
            [child.as_slice()],
            |row| row.get(0),
        )
        .expect("the child's program is durable");
    let bound_program = kata_program::execution_program::compile_execution_program_from_file(
        &repo_root().join(SUBWORKFLOW_PACK),
        &[repo_root().join("workflows/smoke")],
    )
    .expect("the parent pack checks")
    .stages[&kata_types::workflow::StageId("sub".into())]
        .subworkflow
        .as_ref()
        .expect("sub is a subworkflow")
        .bound
        .program_hash()
        .to_string();
    assert_eq!(
        child_program, bound_program,
        "the child ran the program the parent's check bound"
    );
    assert_eq!(
        containers.len(),
        4,
        "four capsules: before, after, and the child's first and second"
    );
    println!(
        "SUBWORKFLOW oci={parent} child={child_id} \
         child_program={child_program} capsules={} runtime_residue=none",
        containers.len(),
    );
}

/// THE EXIT-STATUS VERDICT, live under oci: a fixture pack whose `gate` authors
/// `exit_policy = "content"` and exits 3 (content IS its verdict), `boom` exits 3 under
/// the default `zero_success` policy, and `after` depends on `boom`.
///
/// Off `kata run show` and raw alike: `failed`. `gate` completed exactly once; `boom`'s
/// last transition is `failed` with the one `ShellNonzeroExit` reason (`exit_code=3`, the
/// stderr tail) and it never completed; `after` has NO attempt. `boom`'s occurrence
/// accepts no outcome and its reason names PERFORMED BUT FAILED; `gate`'s accepted
/// outcome carries `exit_code: 3`; exactly two capsules ran, leaving no residue.
#[test]
#[ignore = "HOST-DEPENDENT like the rest of this binary (a certified rootless youki with its \
            installed AppArmor profile, a delegated user scope, the busybox closure realised, \
            `kata-provider-youki` built). Run alone, one test at a time: `cargo nextest run -p \
            kata -P live-smoke --test oci_main_live --run-ignored all`."]
fn a_nonzero_exit_fails_the_stage_and_never_runs_the_successor_live() {
    let fixture = tempfile::tempdir().expect("a fixture root");
    let pack = fixture.path().join("exit-status.star");
    std::fs::write(&pack, EXIT_STATUS_PACK).unwrap();

    let oci_root = tempfile::tempdir().expect("an oci root");
    let oci_config = write_config(oci_root.path(), "oci");
    let (route, _unseal) = provision_provider(oci_root.path());
    let oci_data = oci_root.path().join("data");
    let worker_state = oci_data.join("oci-worker-state");
    let providers_before = cgroup_dirs("kata.provider.*");
    let (oci_doc, containers) = {
        let main = Main::start(oci_root.path(), &oci_config, true, &route);
        let doc = main.run(&pack);
        let containers: Vec<String> = {
            let conn = raw(&oci_data);
            let mut statement = conn.prepare("SELECT capsule_id FROM capsules").unwrap();
            statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .unwrap()
                .map(|capsule| format!("kata-{}", hex::encode(capsule.unwrap())))
                .collect()
        };
        for container in &containers {
            let residue = runtime_residue(&worker_state, container, &providers_before);
            assert!(
                residue.is_empty(),
                "{container} (main up):\n{}",
                describe(&residue)
            );
        }
        (doc, containers)
    };
    for container in &containers {
        let residue = runtime_residue(&worker_state, container, &providers_before);
        assert!(
            residue.is_empty(),
            "{container} (main stopped):\n{}",
            describe(&residue)
        );
    }
    assert_eq!(oci_doc["status"], "failed", "{oci_doc}");
    let (gate_state, gate_reason, gate_completed, _) = raw_stage_end(&oci_data, "gate");
    assert_eq!(
        (gate_state.as_deref(), gate_completed),
        (Some("completed"), 1),
        "the content-policy stage completed: {gate_reason}"
    );
    let (boom_state, boom_reason, boom_completed, _) = raw_stage_end(&oci_data, "boom");
    assert_eq!(boom_state.as_deref(), Some("failed"), "{boom_reason}");
    assert!(
        boom_reason.contains(kata_types::workflow::SHELL_NONZERO_EXIT_ERROR_PREFIX)
            && boom_reason.contains("exit_code=3")
            && boom_reason.contains("boom-err"),
        "the one ShellNonzeroExit reason: {boom_reason}"
    );
    assert_eq!(boom_completed, 0, "boom never completed");
    let (_, _, _, after_attempts) = raw_stage_end(&oci_data, "after");
    assert_eq!(after_attempts, 0, "the successor never ran");
    assert!(
        boom_reason.contains("PERFORMED BUT FAILED"),
        "{boom_reason}"
    );
    let accepted_boom: i64 = raw(&oci_data)
        .query_row(
            "SELECT count(*) FROM occurrences o JOIN attempts a
                ON a.attempt_id = o.accepted_attempt_id WHERE a.stage_id = 'boom'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(accepted_boom, 0, "boom's occurrence accepts no outcome");
    let gate_exit: i64 = raw(&oci_data)
        .query_row(
            "SELECT json_extract(t.payload_json, '$.output.exit_code') FROM transitions t
               JOIN attempts a ON a.attempt_id = t.attempt_id
              WHERE a.stage_id = 'gate' AND t.resulting_state = 'completed'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(gate_exit, 3, "the content-policy exit code is content");
    assert_eq!(containers.len(), 2, "two capsules: gate, boom");
    println!(
        "EXIT-STATUS oci={} boom_state=failed after_attempts=0 capsules=2 \
         runtime_residue=none",
        oci_doc["id"],
    );
}

/// THE CAPTURE BOUND, live under oci: a fixture pack whose `full` prints exactly the
/// authored `output_bytes` bound, `big` prints one byte past it, and `after` depends on
/// `big`. `kata run show` serves `failed`; raw, `full` completed once, `big`'s last
/// transition is `failed` under the capture judgement's `KILLED ... exceeding its
/// combined capture bound` reason with PERFORMED BUT FAILED, its occurrence accepts
/// nothing, `after` never ran, and neither capsule leaves runtime state.
#[test]
#[ignore = "HOST-DEPENDENT like the rest of this binary (a certified rootless youki with its \
            installed AppArmor profile, a delegated user scope, the busybox closure realised, \
            `kata-provider-youki` built). Run alone, one test at a time: `cargo nextest run -p \
            kata -P live-smoke --test oci_main_live --run-ignored all`."]
fn a_capture_past_the_bound_fails_the_stage_live() {
    let fixture = tempfile::tempdir().expect("a fixture root");
    let pack = fixture.path().join("capture-bound.star");
    std::fs::write(&pack, CAPTURE_PACK).unwrap();

    let oci_root = tempfile::tempdir().expect("an oci root");
    let oci_config = write_config(oci_root.path(), "oci");
    let (route, _unseal) = provision_provider(oci_root.path());
    let oci_data = oci_root.path().join("data");
    let worker_state = oci_data.join("oci-worker-state");
    let providers_before = cgroup_dirs("kata.provider.*");
    let (oci_doc, containers) = {
        let main = Main::start(oci_root.path(), &oci_config, true, &route);
        let doc = main.run(&pack);
        let containers: Vec<String> = {
            let conn = raw(&oci_data);
            let mut statement = conn.prepare("SELECT capsule_id FROM capsules").unwrap();
            statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .unwrap()
                .map(|capsule| format!("kata-{}", hex::encode(capsule.unwrap())))
                .collect()
        };
        for container in &containers {
            let residue = runtime_residue(&worker_state, container, &providers_before);
            assert!(
                residue.is_empty(),
                "{container} (main up):\n{}",
                describe(&residue)
            );
        }
        (doc, containers)
    };
    for container in &containers {
        let residue = runtime_residue(&worker_state, container, &providers_before);
        assert!(
            residue.is_empty(),
            "{container} (main stopped):\n{}",
            describe(&residue)
        );
    }
    assert_eq!(oci_doc["status"], "failed", "{oci_doc}");
    let (full_state, _, full_completed, _) = raw_stage_end(&oci_data, "full");
    assert_eq!(
        (full_state.as_deref(), full_completed),
        (Some("completed"), 1),
        "the at-bound stage completed once"
    );
    let (big_state, big_reason, big_completed, _) = raw_stage_end(&oci_data, "big");
    assert_eq!(big_state.as_deref(), Some("failed"), "{big_reason}");
    assert!(
        big_reason.contains(kata_types::workflow::SHELL_CAPTURE_TRUNCATED_MARKER)
            && big_reason.contains("PERFORMED BUT FAILED"),
        "the provider capture judgement and the verdict: {big_reason}"
    );
    assert_eq!(big_completed, 0, "big never completed");
    let (_, _, _, after_attempts) = raw_stage_end(&oci_data, "after");
    assert_eq!(after_attempts, 0, "the successor never ran");
    let accepted_big: i64 = raw(&oci_data)
        .query_row(
            "SELECT count(*) FROM occurrences o JOIN attempts a
                ON a.attempt_id = o.accepted_attempt_id WHERE a.stage_id = 'big'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(accepted_big, 0, "big's occurrence accepts no outcome");
    assert_eq!(containers.len(), 2, "two capsules: full, big");
    println!(
        "CAPTURE oci={} big_state=failed after_attempts=0 capsules=2 runtime_residue=none",
        oci_doc["id"],
    );
}
