//! The node `kata serve` starts and supervises: one `kata-worker` process.
//!
//! `kata serve` hosts no worker. A `[[workers.transports]] type =
//! "supervised_node"` entry makes it start one `kata-worker run` beside it on
//! this host, dialing `<data_dir>/node.sock`, and start it again when it ends.
//! The node is the process that runs capsules and the agent harness, so a
//! defect model output reaches ends the node, never the main; the main settles
//! the node's attempts as it settles any worker's death (PROVEN AMBIGUOUS once a
//! capsule was delivered) and starts a new node.
//!
//! # The node's files
//!
//! Rendered at every boot from the main's config, owner-only, beside the main's
//! stores: `node.toml` (a `WorkerNodeConfig`) and `node.cred` (the local
//! enrollment secret, `local-worker.secret`, in the worker's credential form),
//! each published through a staged `.node-staged-<file>-<pid>` and a rename.
//! The node's durable membrane store is `<data_dir>/idempotency.db` — the
//! worker derives it from its credential's directory — so the node enrolls
//! under the effect domain the data directory has always named, and the main
//! itself no longer holds that store open: one mutable owner at a time, the
//! node while it runs.
//!
//! # Where the node runs: its own cgroup
//!
//! A node certifies rootless containment by running cgroup v2's delegation
//! protocol on the cgroup it STARTS in: it moves itself into a leaf and enables
//! controllers for its children, which the kernel refuses while any other
//! process is a member (measured on the reference host, see the lane probe:
//! with the main still a member, `+memory` to `cgroup.subtree_control` fails
//! and the node is offered no controller). So when the main's own cgroup `C`
//! is delegated to this user, the main moves itself into `C/kata.main`, enables
//! `C`'s controllers for its children, and places each node incarnation into a
//! fresh `C/kata.node`, the child writing `0` to that leaf's `cgroup.procs`
//! before `execve`. When the node ends, the main writes `1` to
//! `C/kata.node/cgroup.kill`, waits for `populated 0`, and removes the subtree
//! before it starts the next node: no capsule process outlives its node.
//!
//! The main takes the delegated branch whenever it can make `C/kata.main` and
//! move itself into it. When it cannot (`C` is not this user's to change, as a
//! foreground `kata serve` in a login session's scope), the node starts in `C`
//! itself. When it can but `C` still holds another process (a user-owned scope
//! shared with the launching shell), offering `C`'s controllers fails with a
//! warning and the node starts in a `kata.node` offered none. Either way the
//! node's own delegation protocol fails, it refuses `oci_route_uncertified` as
//! it would anywhere else, and the main's boot fails naming it.
//!
//! # A node its heartbeat judges dead
//!
//! A node can stop answering without ending: stopped, or hung. The main's
//! heartbeat sweep judges it dead past its deadline and, before it settles any
//! attempt the node holds, asks this supervision to kill it
//! (`kata_workflow::dispatcher::NodeFence`): when the pid the kernel reported for
//! the dead worker's connection (`SO_PEERCRED`) is the pid of the incarnation the
//! supervision holds, unreaped, the main writes `1` to `C/kata.node/cgroup.kill`,
//! reaps the node, waits for `populated 0` and removes the subtree, then answers;
//! the attempts settle after that, and the next node starts after the usual pause
//! and enrolls afresh. So a stopped node never resumes on its old connection, and
//! none of its containers outlives the verdict. Without a delegated cgroup only the
//! node's own process is killed: what it started is left running. Any other pid (an
//! operator's daemon, an incarnation already reaped) kills nothing. The match is by
//! pid: a registration whose process died, still held while its own death is
//! reconciled, would match the running incarnation only if the kernel had given
//! that pid to it across the pause.
//!
//! # A node that does not enroll
//!
//! Until it enrolls a node has no heartbeat to be judged by, so each incarnation
//! gets [`ENROLL_BUDGET`] from its start. The first one's running out fails the
//! boot; a later one that has not enrolled by then (stopped or hung before it
//! dialed) is killed as a fenced node is and replaced after the usual pause. An
//! incarnation has enrolled once a registered worker's connection is open and its
//! `SO_PEERCRED` pid is the incarnation's.
//!
//! # The node's worker slot
//!
//! `node.sock`'s listener admits from a pool of its own, one slot, and every
//! `local_socket` listener shares `workers.max_workers` less that slot
//! (`crate::local_capacity::LocalCapacityRuntime::start`): an operator daemon
//! never takes the node's slot, at boot or while a node is being started
//! again. A dead node's slot frees when the main's reconciliation of its death
//! ends; a node that dials before that is refused, ends, and is started again
//! after the next pause.
//!
//! # The node's binary
//!
//! `kata-worker` beside the running `kata` is resolved at boot and executed by
//! path at every start. An installed unit pins the main's own binary by digest,
//! not this one: rebuilding in place while a main runs makes its next node a
//! `kata-worker` of the new build, whose different executor term only keeps
//! its results out of reuse.

use std::os::fd::{AsRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use kata_transport::WorkerPoolSupervisor;
use kata_types::KataConfig;
use kata_types::config::{WorkerNodeConfig, WorkerSharedSecret};
use kata_types::identity::{WorkerMembraneId, WorkerResource};
use kata_workflow::dispatcher::{Dispatcher, NodeFence};
use tokio::process::Child;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tracing::{info, warn};

/// The socket the supervised node dials, a direct child of the data directory.
pub(crate) const SOCKET_FILE: &str = "node.sock";
/// The node's rendered `WorkerNodeConfig`.
const CONFIG_FILE: &str = "node.toml";
/// The node's credential: the local enrollment secret in the worker's form.
const CREDENTIAL_FILE: &str = "node.cred";
/// The node binary, a sibling of the running `kata`.
const NODE_BINARY: &str = "kata-worker";
/// The main's leaf under its delegated cgroup.
const MAIN_CGROUP: &str = "kata.main";
/// The node's leaf under the main's delegated cgroup.
const NODE_CGROUP: &str = "kata.node";

/// How long a node incarnation has to enroll after it starts: the first one's
/// budget running out fails the boot, a later one's kills it and starts the next.
/// Its capsule route starts a throwaway container to certify the pinned runtime
/// before it dials.
const ENROLL_BUDGET: Duration = Duration::from_secs(180);
/// How often the supervision looks for a node's registration.
const ENROLL_POLL: Duration = Duration::from_millis(100);
/// The first pause before a node that ended is started again; doubled per quick
/// end up to [`RESPAWN_MAX`], reset after a node ran [`STABLE_RUN`].
const RESPAWN_FIRST: Duration = Duration::from_secs(1);
const RESPAWN_MAX: Duration = Duration::from_secs(30);
const STABLE_RUN: Duration = Duration::from_secs(60);
/// How long a stop waits for the node to leave on its own (its connection is
/// already closed) before the main kills its subtree.
const STOP_GRACE: Duration = Duration::from_secs(5);
/// How long the main waits for a killed node subtree to report `populated 0`.
const SUBTREE_EMPTY_BUDGET: Duration = Duration::from_secs(10);

/// The socket path a `supervised_node` transport binds.
pub(crate) fn socket_path(data_dir: &Path) -> PathBuf {
    data_dir.join(SOCKET_FILE)
}

/// What the supervision loop is allowed to do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Control {
    /// Keep a node running: start a new one when it ends.
    Run,
    /// Shutdown began: start no new node, let the running one finish.
    NoRespawn,
    /// Stop: wait [`STOP_GRACE`] for the node, then kill its subtree.
    Stop,
}

/// The running supervision of one node.
pub(crate) struct SupervisedNode {
    control: watch::Sender<Control>,
    /// Ends `Ok(clean)` only after a stop; `Err` when a node can no longer be
    /// started or its subtree cannot be emptied, which fails the main closed.
    task: JoinHandle<Result<bool>>,
}

impl SupervisedNode {
    /// Render the node's files, place the main, start the first node and wait
    /// until it enrolled (under `membrane`, which its config names), then install
    /// this supervision's fence in `dispatcher`. A node that ends before it
    /// enrolls, or has not enrolled within [`ENROLL_BUDGET`], fails the boot: its
    /// own refusal is on the shared stderr above.
    pub(crate) async fn start(
        cfg: &KataConfig,
        supervisor: &Arc<WorkerPoolSupervisor>,
        dispatcher: &Dispatcher,
        membrane: WorkerMembraneId,
    ) -> Result<Self> {
        let launch = NodeLaunch::prepare(cfg, membrane)?;
        let enrollment = Enrollment {
            supervisor: Arc::clone(supervisor),
            budget: ENROLL_BUDGET,
        };
        let mut child = launch.spawn()?;
        info!(
            pid = child.id(),
            binary = %launch.binary.display(),
            placement = %launch.placement.describe(),
            "supervised node started; waiting for it to enroll"
        );
        if let Err(error) = wait_enrolled(&enrollment, &mut child).await {
            let _ = child.start_kill();
            let _ = child.wait().await;
            launch.placement.empty_node_subtree().await?;
            return Err(error);
        }
        let (control, rx) = watch::channel(Control::Run);
        let (requests, fences) = mpsc::unbounded_channel();
        let task = tokio::spawn(supervise(launch, child, rx, fences, enrollment));
        dispatcher
            .install_node_fence(Arc::new(Fence { requests }))
            .context("installing the supervised node's fence")?;
        Ok(Self { control, task })
    }

    /// Resolve only when supervision failed: a node could not be started again
    /// or its subtree could not be emptied. The main fails closed on it.
    pub(crate) async fn wait_for_failure(&mut self) -> anyhow::Error {
        match (&mut self.task).await {
            Ok(Err(error)) => error,
            Ok(Ok(_)) => anyhow::anyhow!("node supervision ended without a stop request"),
            Err(join) => anyhow::Error::new(join).context("node supervision task failed"),
        }
    }

    /// Start no further node: shutdown began.
    pub(crate) fn stop_respawning(&self) {
        let _ = self.control.send(Control::NoRespawn);
    }

    /// Stop the node: it leaves on its own once its connection closed, and its
    /// subtree is killed after [`STOP_GRACE`]. True when it left within the grace
    /// and its subtree emptied.
    pub(crate) async fn stop(self) -> bool {
        let _ = self.control.send(Control::Stop);
        match tokio::time::timeout(
            STOP_GRACE + SUBTREE_EMPTY_BUDGET + Duration::from_secs(2),
            self.task,
        )
        .await
        {
            Ok(Ok(Ok(clean))) => clean,
            Ok(Ok(Err(error))) => {
                warn!(error = %format!("{error:#}"), "supervised node stopped uncleanly");
                false
            }
            Ok(Err(error)) => {
                warn!(%error, "node supervision task failed during shutdown");
                false
            }
            Err(_) => {
                warn!("node supervision did not finish within its shutdown budget");
                false
            }
        }
    }
}

/// One request of the dispatcher's to kill the node whose process is `pid`.
struct FenceRequest {
    pid: u32,
    /// What [`NodeFence::fence`] answers.
    killed: oneshot::Sender<Result<Option<String>, String>>,
}

/// The dispatcher's handle on this supervision: each fence is answered by the
/// supervision loop, the one owner of the node's process and subtree.
struct Fence {
    requests: mpsc::UnboundedSender<FenceRequest>,
}

impl NodeFence for Fence {
    fn fence(
        &self,
        pid: u32,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<Option<String>, String>> + Send + '_>> {
        Box::pin(async move {
            let (killed, answer) = oneshot::channel();
            self.requests
                .send(FenceRequest { pid, killed })
                .map_err(|_| "the node's supervision has ended".to_owned())?;
            answer
                .await
                .map_err(|_| "the node's supervision ended before it answered".to_owned())?
        })
    }
}

/// How the supervision tells that a node incarnation enrolled, and how long it
/// gives each one.
struct Enrollment {
    supervisor: Arc<WorkerPoolSupervisor>,
    budget: Duration,
}

impl Enrollment {
    /// True while a registered worker's connection is open and its process (the
    /// kernel's `SO_PEERCRED` pid) is `pid`.
    fn holds(&self, pid: u32) -> bool {
        self.supervisor
            .iter_workers()
            .any(|worker| worker.peer_pid() == Some(pid) && worker.is_alive())
    }
}

/// Everything one node incarnation needs.
struct NodeLaunch {
    binary: PathBuf,
    config: PathBuf,
    data_dir: PathBuf,
    placement: Placement,
}

impl NodeLaunch {
    fn prepare(cfg: &KataConfig, membrane: WorkerMembraneId) -> Result<Self> {
        let binary = node_binary()?;
        let config = render_node_files(cfg, membrane)?;
        Ok(Self {
            binary,
            config,
            data_dir: cfg.node.data_dir.clone(),
            placement: Placement::prepare(),
        })
    }

    /// Start one node incarnation, in a fresh node cgroup when the main's is
    /// delegated. The node inherits the main's environment (its provider
    /// declaration and every `env:<VAR>` key), stdout and stderr, and loads no
    /// `.env` of its own.
    fn spawn(&self) -> Result<Child> {
        let mut command = std::process::Command::new(&self.binary);
        command
            .arg("run")
            .arg("--config")
            .arg(&self.config)
            // The daemon's pidfile directory: one node per data directory.
            .env("KATA_DATA_DIR", &self.data_dir)
            // The main made this process tree's `.env` decision when it started
            // (an installed service loads none: it runs under its install-time
            // snapshot), and the node inherits the result. A `kata-worker` loads
            // `.env` from its working directory unless this marker is present.
            .env(kata_types::KATA_NO_DOTENV, "")
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        if let Placement::Delegated { root } = &self.placement {
            let procs = open_node_cgroup(root)?;
            place_child_into(&mut command, procs);
        }
        let mut command = tokio::process::Command::from(command);
        command.kill_on_drop(true);
        command.spawn().with_context(|| {
            format!(
                "starting the supervised node {} --config {}",
                self.binary.display(),
                self.config.display()
            )
        })
    }
}

/// The supervision loop: wait for the node to end, or kill it when a fence names
/// it or it has not enrolled within its budget, empty its subtree, and start the
/// next one unless shutdown began. Every fence is answered, in the pause between
/// nodes too.
async fn supervise(
    launch: NodeLaunch,
    mut child: Child,
    mut control: watch::Receiver<Control>,
    mut fences: mpsc::UnboundedReceiver<FenceRequest>,
    enrollment: Enrollment,
) -> Result<bool> {
    let mut backoff = RESPAWN_FIRST;
    loop {
        let started = Instant::now();
        // Until this incarnation enrolls it has no heartbeat that could judge it
        // dead, so its enrollment budget is what bounds a stall before it dials.
        let mut enrolled = false;
        let status = loop {
            tokio::select! {
                status = child.wait() => break status.context("waiting for the supervised node")?,
                () = tokio::time::sleep(ENROLL_POLL), if !enrolled => {
                    let pid = child.id().unwrap_or_default();
                    if enrollment.holds(pid) {
                        enrolled = true;
                        info!(pid, "supervised node enrolled");
                    } else if started.elapsed() >= enrollment.budget {
                        warn!(
                            pid,
                            budget_s = enrollment.budget.as_secs_f64(),
                            "the supervised node did not enroll within its budget; killing it"
                        );
                        break launch.placement.kill_node(&mut child).await?.0;
                    }
                }
                () = until(&mut control, Control::Stop) => {
                    let left = tokio::time::timeout(STOP_GRACE, child.wait()).await;
                    if left.is_err() {
                        warn!(
                            "the supervised node did not leave within its stop grace; killing it"
                        );
                        let _ = child.start_kill();
                        let _ = child.wait().await;
                    }
                    launch.placement.empty_node_subtree().await?;
                    return Ok(left.is_ok());
                }
                Some(request) = fences.recv() => {
                    // The child is unreaped until this loop reaps it, so no other
                    // process holds its pid now (see the module docs for a pid the
                    // kernel reused).
                    if child.id() != Some(request.pid) {
                        let _ = request.killed.send(Ok(None));
                        continue;
                    }
                    warn!(
                        pid = request.pid,
                        "the supervised node's heartbeat judged it dead; killing it before its \
                         attempts settle"
                    );
                    match launch.placement.kill_node(&mut child).await {
                        Ok((status, killed)) => {
                            let _ = request.killed.send(Ok(Some(killed)));
                            break status;
                        }
                        Err(error) => {
                            let _ = request.killed.send(Err(format!("{error:#}")));
                            return Err(error);
                        }
                    }
                }
            }
        };
        launch.placement.empty_node_subtree().await?;
        if *control.borrow() != Control::Run {
            info!(%status, "supervised node left during shutdown");
            return Ok(true);
        }
        if started.elapsed() >= STABLE_RUN {
            backoff = RESPAWN_FIRST;
        }
        warn!(
            %status,
            restart_in_ms = backoff.as_millis(),
            "supervised node ended; its attempts settle by the main's worker-death \
             reconciliation, and a new node starts"
        );
        let pause = tokio::time::sleep(backoff);
        tokio::pin!(pause);
        loop {
            tokio::select! {
                () = &mut pause => break,
                () = until(&mut control, Control::NoRespawn) => return Ok(true),
                // No node runs in the pause, so no fence names one.
                Some(request) = fences.recv() => {
                    let _ = request.killed.send(Ok(None));
                }
            }
        }
        backoff = (backoff * 2).min(RESPAWN_MAX);
        child = launch.spawn()?;
        info!(pid = child.id(), "supervised node started again");
    }
}

/// Resolve once `control` reads `at_least` or later (`Stop` is past
/// `NoRespawn`), or when the sender is gone.
async fn until(control: &mut watch::Receiver<Control>, at_least: Control) {
    let reached = |value: &Control| match at_least {
        Control::Run => true,
        Control::NoRespawn => *value != Control::Run,
        Control::Stop => *value == Control::Stop,
    };
    let _ = control.wait_for(reached).await;
}

/// Wait until the first node `child` enrolled, failing when it ends first or
/// its budget runs out.
async fn wait_enrolled(enrollment: &Enrollment, child: &mut Child) -> Result<()> {
    let pid = child.id().unwrap_or_default();
    let deadline = Instant::now() + enrollment.budget;
    loop {
        if enrollment.holds(pid) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "the supervised node did not enroll within {}s; its log is on this \
                 process's stderr",
                enrollment.budget.as_secs()
            );
        }
        tokio::select! {
            status = child.wait() => {
                let status = status.context("waiting for the supervised node")?;
                bail!(
                    "the supervised node ended before it enrolled ({status}); its refusal is \
                     on this process's stderr above"
                );
            }
            () = tokio::time::sleep(ENROLL_POLL) => {}
        }
    }
}

/// A `test-support` build's door: the node binary a main run from a test
/// binary (which has no `kata-worker` beside it) starts. A shipped binary has
/// no such door.
#[cfg(any(test, feature = "test-support"))]
pub(crate) const TEST_NODE_BINARY_ENV: &str = "KATA_TEST_SUPERVISED_NODE_BINARY";

/// `kata-worker` beside the running `kata`, or a refusal naming where it was
/// looked for.
fn node_binary() -> Result<PathBuf> {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(binary) = std::env::var_os(TEST_NODE_BINARY_ENV) {
        return Ok(PathBuf::from(binary));
    }
    let running = std::env::current_exe().context("resolving the running kata executable")?;
    let binary = running.with_file_name(NODE_BINARY);
    if !binary.is_file() {
        bail!(
            "supervised_node_binary_absent: the node binary `{NODE_BINARY}` is not at {}, beside \
             the running `kata`; `cargo build --release` builds both — link both onto PATH",
            binary.display()
        );
    }
    Ok(binary)
}

/// Write `node.cred` and `node.toml` for this boot and return the config path.
fn render_node_files(cfg: &KataConfig, membrane: WorkerMembraneId) -> Result<PathBuf> {
    let data_dir = &cfg.node.data_dir;
    let secret = crate::local_capacity::load_or_create_enrollment_secret(data_dir)?;
    let credential = data_dir.join(CREDENTIAL_FILE);
    write_owner_only(
        &credential,
        &toml::to_string_pretty(&WorkerSharedSecret { secret })
            .context("serializing the supervised node's credential")?,
    )?;
    let (labels, _default) = crate::backend_factory::node_capabilities(cfg);
    let capabilities = labels
        .into_iter()
        // The daemon advertises `agent:shell` itself.
        .filter(|label| label != "agent:shell")
        .map(|label| WorkerResource::Custom(label.into()))
        .collect();
    let node = WorkerNodeConfig {
        home_node_endpoint: format!("unix://{}", socket_path(data_dir).display()),
        credential_path: credential,
        expected_membrane_id: membrane,
        capabilities,
        main_data_dir: Some(data_dir.clone()),
    };
    let path = data_dir.join(CONFIG_FILE);
    write_owner_only(
        &path,
        &toml::to_string_pretty(&node).context("serializing the supervised node's config")?,
    )?;
    Ok(path)
}

/// The prefix of a node file's staged half, named in the durable-asset map's
/// publish-through-rename residue (`kata_core::durable_assets`).
const STAGED_PREFIX: &str = ".node-staged-";

/// Replace `path` with `contents`, mode 0600, through a sibling
/// `.node-staged-<file>-<pid>` and a rename. A main killed between the two
/// leaves that sibling behind.
fn write_owner_only(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = path
        .file_name()
        .and_then(|name| name.to_str())
        .with_context(|| format!("{} names no file", path.display()))?;
    let staged = path.with_file_name(format!("{STAGED_PREFIX}{file}-{}", std::process::id()));
    let _ = std::fs::remove_file(&staged);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staged)
        .with_context(|| format!("creating {}", staged.display()))?;
    file.write_all(contents.as_bytes())
        .and_then(|()| file.sync_all())
        .with_context(|| format!("writing {}", staged.display()))?;
    std::fs::rename(&staged, path).with_context(|| format!("publishing {}", path.display()))?;
    Ok(())
}

/// Where node incarnations run.
#[derive(Debug)]
enum Placement {
    /// The main's cgroup `root` is delegated: the main moved itself into
    /// `root/kata.main`, and each node starts in a fresh `root/kata.node`.
    Delegated { root: PathBuf },
    /// The node starts in the main's own cgroup, which is not delegated.
    Inherited { reason: String },
}

impl Placement {
    /// Move the main out of its cgroup and offer that cgroup's controllers to
    /// its children, or say why the node will start in the main's cgroup.
    fn prepare() -> Self {
        let root = match own_cgroup() {
            Ok(root) => root,
            Err(reason) => return Self::Inherited { reason },
        };
        let main = root.join(MAIN_CGROUP);
        if let Err(error) = std::fs::create_dir(&main)
            && error.kind() != std::io::ErrorKind::AlreadyExists
        {
            return Self::Inherited {
                reason: format!("mkdir {}: {error}", main.display()),
            };
        }
        // cgroup v2 reads `0` as the writing process: the whole main moves.
        if let Err(error) = std::fs::write(main.join("cgroup.procs"), "0\n") {
            return Self::Inherited {
                reason: format!("moving the main into {}: {error}", main.display()),
            };
        }
        let offered = std::fs::read_to_string(root.join("cgroup.controllers")).unwrap_or_default();
        for controller in offered.split_whitespace() {
            if let Err(error) = std::fs::write(
                root.join("cgroup.subtree_control"),
                format!("+{controller}"),
            ) {
                warn!(
                    controller,
                    cgroup = %root.display(),
                    %error,
                    "could not offer a controller to the supervised node's cgroup"
                );
            }
        }
        Self::Delegated { root }
    }

    fn describe(&self) -> String {
        match self {
            Self::Delegated { root } => format!("{}", root.join(NODE_CGROUP).display()),
            Self::Inherited { reason } => format!("the main's own cgroup ({reason})"),
        }
    }

    /// Kill the running node `child` with everything it started, reap it, and
    /// wait until its subtree is empty; return its exit status and what was
    /// killed, for the settlement's record. A subtree that stays populated fails
    /// supervision closed.
    async fn kill_node(&self, child: &mut Child) -> Result<(std::process::ExitStatus, String)> {
        let pid = child.id().unwrap_or_default();
        let killed = match self {
            Self::Delegated { root } => {
                let leaf = root.join(NODE_CGROUP);
                std::fs::write(leaf.join("cgroup.kill"), "1")
                    .with_context(|| format!("killing the node subtree {}", leaf.display()))?;
                format!(
                    "the main killed its node, process {pid}, with its subtree {} (cgroup.kill)",
                    leaf.display()
                )
            }
            Self::Inherited { .. } => {
                child.start_kill().context("killing the supervised node")?;
                format!("the main killed its node, process {pid}")
            }
        };
        let status = child
            .wait()
            .await
            .context("reaping the killed supervised node")?;
        self.empty_node_subtree().await?;
        Ok((status, killed))
    }

    /// Kill every process left in the node's subtree, wait for it to empty, and
    /// remove it. A subtree that stays populated fails supervision closed.
    async fn empty_node_subtree(&self) -> Result<()> {
        let Self::Delegated { root } = self else {
            return Ok(());
        };
        let leaf = root.join(NODE_CGROUP);
        if !leaf.exists() {
            return Ok(());
        }
        std::fs::write(leaf.join("cgroup.kill"), "1")
            .with_context(|| format!("killing the node subtree {}", leaf.display()))?;
        let deadline = Instant::now() + SUBTREE_EMPTY_BUDGET;
        loop {
            let events = std::fs::read_to_string(leaf.join("cgroup.events")).unwrap_or_default();
            if events.lines().any(|line| line == "populated 0") {
                break;
            }
            if Instant::now() >= deadline {
                bail!(
                    "the supervised node's subtree {} is still populated {}s after cgroup.kill",
                    leaf.display(),
                    SUBTREE_EMPTY_BUDGET.as_secs()
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        remove_cgroup_tree(&leaf)
            .with_context(|| format!("removing the node subtree {}", leaf.display()))
    }
}

/// The cgroup v2 directory this process is a member of.
fn own_cgroup() -> std::result::Result<PathBuf, String> {
    const ROOT: &str = "/sys/fs/cgroup";
    if !Path::new(ROOT).join("cgroup.controllers").exists() {
        return Err(format!("{ROOT} is not a cgroup v2 unified hierarchy"));
    }
    let membership = std::fs::read_to_string("/proc/self/cgroup")
        .map_err(|error| format!("reading /proc/self/cgroup: {error}"))?;
    let relative = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| "/proc/self/cgroup has no cgroup v2 (`0::`) line".to_owned())?;
    Ok(Path::new(ROOT).join(relative.trim_start_matches('/')))
}

/// Remove `leaf` and every cgroup below it, deepest first. Only empty cgroups
/// can be removed, which is why the caller emptied it first.
fn remove_cgroup_tree(leaf: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(leaf)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            remove_cgroup_tree(&entry.path())?;
        }
    }
    std::fs::remove_dir(leaf)
}

/// Make a fresh `root/kata.node`, emptying what a previous incarnation left,
/// and open its `cgroup.procs` for the child to place itself.
fn open_node_cgroup(root: &Path) -> Result<OwnedFd> {
    let leaf = root.join(NODE_CGROUP);
    if leaf.exists() {
        // Boot found a node subtree no live supervision owns (an earlier main in
        // this cgroup). Every member is killed before anything is reused.
        std::fs::write(leaf.join("cgroup.kill"), "1")
            .with_context(|| format!("killing the stale node subtree {}", leaf.display()))?;
        let deadline = Instant::now() + SUBTREE_EMPTY_BUDGET;
        while !std::fs::read_to_string(leaf.join("cgroup.events"))
            .unwrap_or_default()
            .lines()
            .any(|line| line == "populated 0")
        {
            if Instant::now() >= deadline {
                bail!("the stale node subtree {} did not empty", leaf.display());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        remove_cgroup_tree(&leaf)
            .with_context(|| format!("removing the stale node subtree {}", leaf.display()))?;
    }
    std::fs::create_dir(&leaf).with_context(|| format!("creating {}", leaf.display()))?;
    // `std` opens close-on-exec, so the descriptor ends at the node's `execve`.
    let procs = std::fs::OpenOptions::new()
        .write(true)
        .open(leaf.join("cgroup.procs"))
        .with_context(|| format!("opening {}/cgroup.procs", leaf.display()))?;
    Ok(OwnedFd::from(procs))
}

/// Have the child place itself into the cgroup whose `cgroup.procs` is `procs`
/// before `execve`; a refused write aborts the spawn.
#[allow(unsafe_code)]
fn place_child_into(command: &mut std::process::Command, procs: OwnedFd) {
    use std::os::unix::process::CommandExt as _;
    let fd = procs.as_raw_fd();
    // SAFETY: the closure runs in the post-`fork`, pre-`execve` child. It
    // performs one `write(2)` of two constant bytes onto an already-open
    // descriptor — async-signal-safe and non-allocating. `procs` is MOVED in so
    // the descriptor stays open until `execve` closes it (close-on-exec).
    unsafe {
        command.pre_exec(move || {
            let _keep_open = &procs;
            // cgroup v2 reads a literal `0` as "the calling process".
            let buf = b"0\n";
            let written = libc::write(fd, buf.as_ptr().cast::<libc::c_void>(), buf.len());
            if written != buf.len().cast_signed() {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in node: a script that becomes `sleep 60`.
    fn stand_in_launch(dir: &Path) -> NodeLaunch {
        let stand_in = dir.join(NODE_BINARY);
        std::fs::write(&stand_in, "#!/bin/sh\nexec sleep 60\n").expect("write the stand-in node");
        std::fs::set_permissions(
            &stand_in,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .expect("make the stand-in node executable");
        NodeLaunch {
            binary: stand_in,
            config: dir.join(CONFIG_FILE),
            data_dir: dir.to_path_buf(),
            placement: Placement::Inherited {
                reason: "not under test".to_owned(),
            },
        }
    }

    /// An enrollment against a registry no worker joins, so no node enrolls.
    fn unregistered(budget: Duration) -> Enrollment {
        Enrollment {
            supervisor: Arc::new(WorkerPoolSupervisor::new()),
            budget,
        }
    }

    /// `/proc/<pid>/stat`'s parent pid and state letter, or `None` once it is gone.
    fn parent_and_state(pid: u32) -> Option<(u32, char)> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let mut fields = stat.rsplit_once(") ")?.1.split_whitespace();
        let state = fields.next()?.chars().next()?;
        Some((fields.next()?.parse().ok()?, state))
    }

    /// The live (not zombie) children of this process.
    fn live_children() -> Vec<u32> {
        let me = std::process::id();
        std::fs::read_dir("/proc")
            .expect("/proc is readable")
            .flatten()
            .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
            .filter(|pid| {
                parent_and_state(*pid).is_some_and(|(parent, state)| parent == me && state != 'Z')
            })
            .collect()
    }

    /// **A fence kills exactly the node it names, and the next node starts.** The
    /// supervision loop holds a stand-in node, and the dispatcher's fence is asked
    /// about three processes; each answer is checked against `/proc`:
    ///
    /// * a process that is not the node (this test's own) — `None`, and the node
    ///   still runs;
    /// * the node — what was killed, naming its pid, and once that answer arrives
    ///   the node is gone from the process table (killed and reaped);
    /// * the node just killed, asked again during the pause — `None`;
    ///
    /// then a new node, a different process, runs as this process's child, and a
    /// fence naming it during shutdown kills it and ends the supervision cleanly.
    ///
    /// **Would red if:** the loop killed its node for a fence naming any process
    /// (watched, with the pid comparison removed: the first fence killed the node).
    #[tokio::test]
    async fn a_fence_kills_exactly_the_node_it_names_and_the_next_node_starts() {
        let dir = tempfile::tempdir().expect("a node directory");
        let launch = stand_in_launch(dir.path());
        let child = launch.spawn().expect("the stand-in node starts");
        let node = child.id().expect("the stand-in node is running");
        let (control, rx) = watch::channel(Control::Run);
        let (requests, fences) = mpsc::unbounded_channel();
        // No stand-in enrolls; the production budget outlasts this cell.
        let task = tokio::spawn(supervise(
            launch,
            child,
            rx,
            fences,
            unregistered(ENROLL_BUDGET),
        ));
        let fence = Fence { requests };

        let other = std::process::id();
        assert_eq!(
            fence.fence(other).await,
            Ok(None),
            "a fence naming process {other}, not the node, kills nothing"
        );
        assert!(
            parent_and_state(node).is_some_and(|(_, state)| state != 'Z'),
            "the node {node} still runs after a fence that named another process"
        );

        let killed = fence
            .fence(node)
            .await
            .expect("the fence naming the node kills it")
            .expect("the fence names what it killed");
        assert!(
            killed.contains(&format!("process {node}")),
            "the answer names the node's process: {killed}"
        );
        assert!(
            parent_and_state(node).is_none(),
            "the node {node} is still in the process table when the fence answered: {:?}",
            parent_and_state(node)
        );
        assert_eq!(
            fence.fence(node).await,
            Ok(None),
            "the node already killed is no node now"
        );

        let deadline = Instant::now() + Duration::from_secs(30);
        let next = loop {
            if let [next] = live_children()[..]
                && next != node
            {
                break next;
            }
            assert!(
                Instant::now() < deadline,
                "no new node started after the fence: children {:?}",
                live_children()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        let _ = control.send(Control::NoRespawn);
        assert!(
            fence
                .fence(next)
                .await
                .expect("the fence naming the new node kills it")
                .is_some(),
            "the new node {next} was killed"
        );
        let clean = tokio::time::timeout(Duration::from_secs(30), task)
            .await
            .expect("the supervision ends once its node is killed during shutdown")
            .expect("the supervision task did not panic")
            .expect("the supervision ends without error");
        assert!(clean, "the supervision ended cleanly");
        assert!(
            live_children().is_empty(),
            "no node is left: {:?}",
            live_children()
        );
    }

    /// **A node that has not enrolled within its budget is killed, and the next
    /// node starts.** Before it enrolls a node has no heartbeat, so nothing else
    /// could judge a node stopped or hung before it dials. The supervision holds a
    /// stand-in node (`sleep 60`) that never enrolls, under a 500 ms budget; read
    /// off `/proc`: that node leaves the process table long before its sleep could
    /// end, a new node, a different process, then runs as this process's child, and
    /// once shutdown began the supervision ends cleanly, leaving no node.
    ///
    /// **Would red if:** a node's enrollment were bounded only at boot (watched,
    /// with the budget's kill removed: the first node still ran).
    #[tokio::test]
    async fn a_node_that_has_not_enrolled_within_its_budget_is_killed_and_the_next_node_starts() {
        let dir = tempfile::tempdir().expect("a node directory");
        let launch = stand_in_launch(dir.path());
        let child = launch.spawn().expect("the stand-in node starts");
        let node = child.id().expect("the stand-in node is running");
        let (control, rx) = watch::channel(Control::Run);
        let (_requests, fences) = mpsc::unbounded_channel();
        let budget = Duration::from_millis(500);
        let task = tokio::spawn(supervise(launch, child, rx, fences, unregistered(budget)));

        let deadline = Instant::now() + Duration::from_secs(20);
        while parent_and_state(node).is_some() {
            assert!(
                Instant::now() < deadline,
                "the node {node}, never enrolled, still ran 20 s into a {budget:?} enrollment \
                 budget: {:?}",
                parent_and_state(node)
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let next = loop {
            if let [next] = live_children()[..]
                && next != node
            {
                break next;
            }
            assert!(
                Instant::now() < deadline,
                "no new node started after the first was killed: children {:?}",
                live_children()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        let _ = control.send(Control::NoRespawn);
        let clean = tokio::time::timeout(Duration::from_secs(30), task)
            .await
            .expect("the supervision ends once its unenrolled node is killed during shutdown")
            .expect("the supervision task did not panic")
            .expect("the supervision ends without error");
        assert!(clean, "the supervision ended cleanly");
        assert!(
            parent_and_state(next).is_none() && live_children().is_empty(),
            "no node is left: the second node {next} reads {:?}, children {:?}",
            parent_and_state(next),
            live_children()
        );
    }

    /// **The node never loads `.env` itself.** It inherits the main's
    /// environment, which already holds what the main's own `.env` decision
    /// added — nothing under an installed service, which runs under its
    /// install-time snapshot and removes its handoff markers before it starts a
    /// node. A `kata-worker` loads `.env` from its working directory and every
    /// parent unless `KATA_NO_DOTENV` is present (kata-worker's
    /// `no_dotenv_presence_suppresses_ancestor_injection`), so a node started
    /// without the marker would lift values outside that snapshot. Read off the
    /// kernel: the started node's `/proc/<pid>/environ` carries the marker,
    /// though the process that started it carries none.
    ///
    /// **Would red if:** `NodeLaunch::spawn` left the marker off (watched).
    #[tokio::test]
    async fn the_node_starts_with_dotenv_loading_suppressed() {
        let marker = format!("{}=", kata_types::KATA_NO_DOTENV);
        assert!(
            std::env::var_os(kata_types::KATA_NO_DOTENV).is_none(),
            "the premise: the process starting the node carries no {marker}"
        );
        let dir = tempfile::tempdir().expect("a node directory");
        let launch = stand_in_launch(dir.path());
        let mut child = launch.spawn().expect("the stand-in node starts");
        let pid = child.id().expect("the stand-in node is running");
        // Its own environment, once it runs: the launch's `KATA_DATA_DIR` is in it.
        let launched = format!("KATA_DATA_DIR={}", dir.path().display());
        let deadline = Instant::now() + Duration::from_secs(30);
        let environ = loop {
            let environ: Vec<String> = std::fs::read(format!("/proc/{pid}/environ"))
                .unwrap_or_default()
                .split(|byte| *byte == 0)
                .map(|entry| String::from_utf8_lossy(entry).into_owned())
                .collect();
            if environ.contains(&launched) {
                break environ;
            }
            assert!(
                Instant::now() < deadline,
                "the stand-in node (pid {pid}) never ran with its launch environment"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        let _ = child.start_kill();
        let _ = child.wait().await;
        let kata: Vec<&String> = environ
            .iter()
            .filter(|entry| entry.starts_with("KATA_"))
            .collect();
        assert!(
            environ.contains(&marker),
            "the node was started without {marker}, so it would load `.env`; its KATA_ \
             variables: {kata:?}"
        );
    }
}
