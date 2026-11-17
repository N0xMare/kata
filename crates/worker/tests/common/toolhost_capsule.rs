//! The rig of every live binary that runs `kata-toolhost` as the init of a REAL
//! rootless container: a certified route, a provider entry carrying the toolhost at
//! `toolhost/kata-toolhost`, and a nanocode agent capsule placed through the worker's
//! own `InteractiveCapsule`, with the facts its cells read from outside kata — the
//! init's host pid by the pinned runtime, the container's cgroup by the kernel's
//! hierarchy, the attempt root on the host.
//!
//! The provider entry is staged here exactly as an operator's would hold it: the
//! freshly built `kata-provider-youki` beside `toolhost/kata-toolhost`, the static
//! binary `cargo build -p kata-toolhost --target x86_64-unknown-linux-musl` produced
//! ([`TOOLHOST_TARGET`]), or a stand-in init a cell names in its place.
//!
//! Included by path (`#[path = "common/toolhost_capsule.rs"]`) by the binaries that
//! use it, beside their `mod common;`, rather than compiled into every binary that
//! shares `common`.
//!
//! # It REFUSES on a host that cannot prove containment
//!
//! No certified youki, no installed AppArmor profile or no delegated scope is a
//! FAILURE naming the refusal, never a skip.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kata_types::agent::AdapterKind;
use kata_types::error::KataResult;
use kata_types::execution_contract::{
    AgentTurnSpec, ArtifactId, ArtifactPrivacy, Capsule, CapsuleBudgets, CapsuleNetwork,
    CapsuleProcess, EnvironmentId, GuestAccess, GuestMapping, GuestPath, OccurrenceId, PlatformRef,
    PreparedActionId,
};
use kata_types::nix_environment::{
    ClosureEntry, IntegrityPolicy, NarVerification, NixEnvironmentManifest, Provenance,
    RetentionClass, RetentionIntent, StorePath,
};
use kata_types::primitives::{ContentHash, ObjectId};
use kata_types::sandbox::NetPolicy;
use kata_types::tree_artifact::TreeManifest;
use kata_types::youki_pin::YoukiPin;
use kata_worker::execution_route::{ExternalProviderAddress, OciRoute};
use kata_worker::interactive_capsule::{
    InteractiveCapsule, InteractivePlacement, InteractiveTeardown,
};
use kata_worker::materialize::{BlobSource, StorePathProbe, TreeResolver};
use kata_worker::oci_driver::{
    OCI_PROVIDER_NAME, OciProviderInstallation, OciStageDriver, OciStageRequest,
};
use kata_worker::oci_runtime::certify_youki;
use tokio::io::AsyncReadExt as _;

/// The same real store path every OCI live file names: one statically linked busybox
/// is the whole closure, and it is the capsule's `sh`.
pub const BUSYBOX: &str =
    "/nix/store/qddzvnv6b0805nkvbqddbswddcfhx814-busybox-static-x86_64-unknown-linux-musl-1.37.0";
const BUSYBOX_NAR_HASH: &str = "sha256-d7JNm1d4Wo1oSA2pvoRLt1vqyAhSlIsjE0GckcLiSeA=";
const BUSYBOX_NAR_SIZE: u64 = 1_495_056;

/// Where the toolhost's static build lands, relative to the target directory.
pub const TOOLHOST_TARGET: &str = "x86_64-unknown-linux-musl/debug/kata-toolhost";

fn hash(byte: u8) -> ContentHash {
    ContentHash::new([byte; 32])
}

fn environment() -> NixEnvironmentManifest {
    NixEnvironmentManifest::new(
        "toolhost-busybox",
        PlatformRef::new("x86_64-linux", hash(11)),
        Provenance::StorePaths {
            nixpkgs_attribute: "nixpkgs#pkgsStatic.busybox".into(),
        },
        vec![StorePath::new(BUSYBOX).expect("a real store path")],
        vec![ClosureEntry {
            store_path: StorePath::new(BUSYBOX).expect("a real store path"),
            nar_hash: BUSYBOX_NAR_HASH.into(),
            nar_size: BUSYBOX_NAR_SIZE,
            references: vec![],
            ca: None,
        }],
        vec![GuestPath::new(format!("{BUSYBOX}/bin")).expect("the closure's bin directory")],
        IntegrityPolicy {
            verify: NarVerification::NarHashAndSignatures,
            sigs_needed: 1,
            required_signers: vec!["cache.nixos.org-1".into()],
            allow_unsigned_content_addressed: false,
            verify_contents_at_declare: false,
        },
        ArtifactPrivacy::Public,
        RetentionIntent {
            class: RetentionClass::Cache,
        },
        "nix-store --realise",
    )
    .expect("the fixture environment is well formed")
}

fn mapping(path: &str, artifact: u8) -> GuestMapping {
    GuestMapping {
        artifact: ArtifactId(hash(artifact)),
        guest_path: GuestPath::new(path.to_owned()).expect("a guest path"),
        access: GuestAccess::ReadWrite,
    }
}

/// A turn of the nanocode `kind`: its kind fixes the launch, so its argv is EMPTY and
/// the bundle execs `/.kata/kata-toolhost`. No adapter runs at launch; whatever speaks
/// the protocol is the cell's.
fn toolhost_capsule(kind: AdapterKind) -> Capsule {
    Capsule::new(
        OccurrenceId(hash(0x7a)),
        PreparedActionId(hash(2)),
        EnvironmentId(hash(3)),
        PlatformRef::new("x86_64-linux", hash(11)).id(),
        vec![
            mapping("/work", 20),
            mapping("/out", 21),
            mapping("/tmp", 22),
        ],
        CapsuleProcess::Agent(AgentTurnSpec {
            adapter: kind,
            model: None,
            reasoning_effort: None,
            output_schema: None,
            prompt: ArtifactId(hash(0x51)),
            credential: None,
            env: std::collections::BTreeMap::new(),
        }),
        CapsuleNetwork::Offline,
        None,
        CapsuleBudgets {
            wall_time_ms: 90_000,
            output_bytes: 1 << 20,
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
            result_bytes: 4 * 1024 * 1024,
            result_entries: 128,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )
    .expect("the fixture capsule is well formed")
}

/// Every mapped tree is EMPTY.
struct EmptyTrees;

impl TreeResolver for EmptyTrees {
    fn tree_manifest(&self, _artifact: ArtifactId) -> KataResult<TreeManifest> {
        TreeManifest::new(vec![])
    }

    fn tree_reference(
        &self,
        artifact: ArtifactId,
    ) -> KataResult<kata_types::execution_contract::ArtifactRef> {
        panic!("no reference is resolved on this route ({artifact:?})")
    }
}

/// Reached for no member, because every tree is empty.
struct BytesForbidden;

impl BlobSource for BytesForbidden {
    fn read_verified(
        &self,
        object: ObjectId,
        _expected: u64,
        _maximum: u64,
    ) -> KataResult<Vec<u8>> {
        panic!("no member's bytes should be read: every mapped tree is empty ({object:?})")
    }
}

/// The real host's store: the container rbinds the closure at its own store path.
struct RealStore;

impl StorePathProbe for RealStore {
    fn present(&self, path: &StorePath) -> KataResult<bool> {
        Ok(Path::new(path.as_str()).is_dir())
    }
}

const INNER_ENV: &str = "KATA_TOOLHOST_DELEGATED_INNER";

/// Run `body` inside a delegated user scope, re-exec'ing this binary if needed — the
/// shape every OCI live file uses.
pub fn delegated<F>(test: &'static str, body: F)
where
    F: std::future::Future<Output = ()>,
{
    if std::env::var(INNER_ENV).as_deref() == Ok(test) {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a tokio runtime inside the delegated scope")
            .block_on(body);
        return;
    }
    let exe = std::env::current_exe().expect("the test binary's own path");
    let output = std::process::Command::new("systemd-run")
        .args(kata_test_utils::delegated_scope::systemd_run_args())
        .arg(&exe)
        .args([
            "--exact",
            test,
            "--include-ignored",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env(INNER_ENV, test)
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "re-exec of `{test}` inside `systemd-run --user --scope -p Delegate=yes` could not \
                 be spawned ({error}). See `just _containment-preconditions`."
            )
        });
    eprintln!(
        "--- delegated inner run of `{test}` stdout ---\n{}\n--- stderr ---\n{}\n---",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    kata_test_utils::delegated_scope::assert_inner_ran_the_one_test(test, &output);
}

/// The freshly built `kata-provider-youki` next to the test binary.
fn provider_bin() -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary has a path");
    for dir in exe.ancestors().skip(1) {
        let candidate = dir.join("kata-provider-youki");
        if candidate.is_file() {
            crate::common::require_current_provider_protocol(
                "toolhost rig",
                "kata-provider-youki",
                &candidate,
            );
            return candidate;
        }
        if dir.file_name().and_then(|n| n.to_str()) == Some("target") {
            break;
        }
    }
    panic!(
        "`kata-provider-youki` is not next to the test binary. Run `cargo build -p \
         kata-provider-youki --bin kata-provider-youki` in the same command."
    );
}

/// The static `kata-toolhost` this build produced. A stale one is caught by its own
/// `Hello` (the source digest), which every cell checks before any tool frame.
pub fn toolhost_bin() -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary has a path");
    exe.ancestors()
        .skip(1)
        .map(|dir| dir.join(TOOLHOST_TARGET))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| {
            panic!(
                "the static `kata-toolhost` is not under the target directory ({TOOLHOST_TARGET}), \
                 and it IS the subject of this proof. Run `cargo build -p kata-toolhost --target \
                 x86_64-unknown-linux-musl` in the same command."
            )
        })
}

/// Provision the provider with `toolhost` copied to `toolhost/kata-toolhost` beside
/// it, into a by-hash store this rig owns.
fn install_provider(root: &Path, toolhost: &Path) -> OciProviderInstallation {
    let source = root.join("provider-src");
    std::fs::create_dir_all(source.join("toolhost")).expect("the provider source directory");
    std::fs::copy(
        provider_bin(),
        source.join(format!("kata-provider-{OCI_PROVIDER_NAME}")),
    )
    .expect("the provider bytes copy");
    std::fs::copy(toolhost, source.join("toolhost/kata-toolhost"))
        .expect("the toolhost bytes copy");
    let store_root = root.join("provider-store");
    let provisioned = kata_worker::ProviderStore::new(&store_root)
        .provision(OCI_PROVIDER_NAME, &source)
        .expect("the provider provisions into a by-hash store");
    OciProviderInstallation::new(
        store_root,
        ExternalProviderAddress::parse(&provisioned.address.to_string())
            .expect("a minted address parses"),
    )
}

/// A stand-in init for the provider entry's `toolhost/kata-toolhost`, written under
/// `dir`: a busybox script that writes a `Hello` of this protocol stating an all-zero
/// source digest, then records every byte it receives to `/work/received` until its
/// stdin ends.
pub fn stand_in_toolhost(dir: &Path) -> PathBuf {
    let hello = format!(
        r#"{{"kind":"hello","frame":{{"protocol":{},"source_digest":"{}"}}}}"#,
        kata_toolhost_protocol::TOOLHOST_PROTOCOL_VERSION,
        "0".repeat(64)
    );
    let length = u32::try_from(hello.len())
        .unwrap()
        .to_be_bytes()
        .iter()
        .fold(String::new(), |mut octal, byte| {
            use std::fmt::Write as _;
            write!(octal, "\\{byte:03o}").unwrap();
            octal
        });
    let stand_in = dir.join("kata-toolhost");
    std::fs::write(
        &stand_in,
        format!("#!{BUSYBOX}/bin/sh\nprintf '{length}{hello}'\nexec cat > /work/received\n"),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&stand_in, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    stand_in
}

/// `youki --root <state> state <id>`'s answer, read with the pinned runtime, or what it
/// printed instead of JSON (nothing, for a container it does not know, yet or any
/// more) with the parse error.
pub fn runtime_state(state: &Path, container: &str) -> Result<serde_json::Value, String> {
    let output = std::process::Command::new(YoukiPin::embedded().store_path())
        .arg("--root")
        .arg(state)
        .args(["state", container])
        .output()
        .expect("the pinned runtime reports the container's state");
    serde_json::from_slice(&output.stdout).map_err(|error| {
        format!(
            "`youki state {container}` is not JSON ({error}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

/// `youki --root <state> state <id>`'s `pid`: the container init's HOST pid, read with
/// the pinned runtime.
pub fn init_host_pid(state: &Path, container: &str) -> u32 {
    let state = runtime_state(state, container).unwrap_or_else(|error| panic!("{error}"));
    state["pid"]
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
        .unwrap_or_else(|| panic!("`youki state {container}` names no pid: {state}"))
}

/// Every pid a `cgroup.procs` at or beneath `dir` lists: the container's tasks as the
/// KERNEL accounts them, sorted. An absent directory lists none.
pub fn cgroup_tasks(dir: &Path) -> Vec<u32> {
    let mut tasks: Vec<u32> = std::fs::read_to_string(dir.join("cgroup.procs"))
        .unwrap_or_default()
        .lines()
        .filter_map(|pid| pid.trim().parse().ok())
        .collect();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                tasks.extend(cgroup_tasks(&entry.path()));
            }
        }
    }
    tasks.sort_unstable();
    tasks
}

/// The last field of `/proc/<pid>/status`'s `NSpid`: the pid inside the innermost
/// namespace.
pub fn namespace_pid(host_pid: u32) -> Option<u32> {
    std::fs::read_to_string(format!("/proc/{host_pid}/status"))
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:"))?
        .split_whitespace()
        .last()?
        .parse()
        .ok()
}

/// Poll `probe` until it holds, or fail after `within` naming `what` and the last
/// value seen.
pub async fn eventually<T: std::fmt::Debug>(
    within: Duration,
    what: &str,
    probe: impl Fn() -> T,
    holds: impl Fn(&T) -> bool,
) -> T {
    let deadline = Instant::now() + within;
    loop {
        let value = probe();
        if holds(&value) {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "{what} did not hold within {within:?}; last seen {value:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The cell's whole rig: a certified route, a provider entry carrying a toolhost,
/// and the capsule's own request. Held for the cell's lifetime; `_unseal` drops before
/// the `TempDir` so the sealed store can be removed.
pub struct Rig {
    driver: OciStageDriver,
    environment: NixEnvironmentManifest,
    capsule: Capsule,
    _unseal: kata_worker::UnsealOnDrop,
    _root: tempfile::TempDir,
}

impl Rig {
    /// A `nanocode_openai` capsule over this build's static toolhost.
    pub fn new() -> Self {
        Self::with_toolhost(&toolhost_bin())
    }

    /// A `nanocode_openai` capsule over `toolhost`'s bytes as the entry's
    /// `toolhost/kata-toolhost`.
    pub fn with_toolhost(toolhost: &Path) -> Self {
        Self::of_kind(AdapterKind::NanocodeOpenai, toolhost)
    }

    /// A capsule of the nanocode `kind` over `toolhost`'s bytes as the entry's
    /// `toolhost/kata-toolhost`.
    pub fn of_kind(kind: AdapterKind, toolhost: &Path) -> Self {
        assert!(
            Path::new(BUSYBOX).join("bin/busybox").is_file(),
            "the closure's only store object is not realised at {BUSYBOX}. Realise it with \
             `nix-store --realise {BUSYBOX}`."
        );
        let certification = certify_youki(YoukiPin::embedded()).unwrap_or_else(|refusal| {
            panic!(
                "this host cannot deliver the rootless-OCI prerequisite, so there is no capsule \
                 for a toolhost to be the init of: {refusal}. `just _containment-preconditions` \
                 gives the one-line diagnosis."
            )
        });
        let root = tempfile::tempdir().expect("a temporary worker state root");
        let unseal = kata_worker::UnsealOnDrop::new(root.path());
        let driver = OciStageDriver::new(
            OciRoute::new(certification),
            root.path().join("worker-state"),
            install_provider(root.path(), toolhost),
        );
        Self {
            driver,
            environment: environment(),
            capsule: toolhost_capsule(kind),
            _unseal: unseal,
            _root: root,
        }
    }

    /// The capsule the rig places.
    pub fn capsule(&self) -> &Capsule {
        &self.capsule
    }

    /// Launch the capsule and split it into its process half and the placement's
    /// teardown half. The toolhost's stderr is taken here and drained into a buffer a
    /// failure message can print, so a diagnostic can never fill its pipe; its stdin
    /// and stdout are left on the process for the cell's speaker.
    pub async fn place(&self, tag: &str) -> Placed {
        let request = OciStageRequest {
            capsule: &self.capsule,
            environment: &self.environment,
            network: NetPolicy::Offline,
            trees: &EmptyTrees,
            source: &BytesForbidden,
            probe: &RealStore,
            execution_id: ulid::Ulid::new(),
        };
        let capsule = InteractiveCapsule::launch(&self.driver, tag, &request)
            .await
            .unwrap_or_else(|refusal| panic!("the toolhost capsule did not start: {refusal}"));
        let state = capsule.runtime_state().to_path_buf();
        let container = capsule.container_id().to_owned();
        let attempt_root = capsule.attempt_root().to_path_buf();
        let (mut process, placement) = InteractivePlacement::into_halves(Box::new(capsule));
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let mut pipe = process.take_stderr().expect("the toolhost's stderr");
        let sink = Arc::clone(&stderr);
        tokio::spawn(async move {
            let mut buffer = [0_u8; 4096];
            while let Ok(read) = pipe.read(&mut buffer).await {
                if read == 0 {
                    break;
                }
                sink.lock().unwrap().extend_from_slice(&buffer[..read]);
            }
        });
        Placed {
            process,
            placement,
            container,
            state,
            attempt_root,
            stderr,
        }
    }
}

/// One placed capsule: its process half (stdin and stdout still on it), its
/// teardown half, and the facts the cells read from outside kata.
pub struct Placed {
    pub process: Box<dyn kata_agent::adapter::InteractiveProcess>,
    pub placement: Box<dyn InteractiveTeardown>,
    pub container: String,
    pub state: PathBuf,
    pub attempt_root: PathBuf,
    pub stderr: Arc<Mutex<Vec<u8>>>,
}

impl Placed {
    /// The init's host pid, by the pinned runtime.
    pub fn init_pid(&self) -> u32 {
        init_host_pid(&self.state, &self.container)
    }

    /// The kata-owned parent cgroup of this container, found from the kernel's view.
    /// Read while the container is provably alive, so a later absence is about a
    /// directory that existed.
    pub fn cgroup(&self) -> PathBuf {
        cgroup_of(&self.container)
    }

    pub fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.stderr.lock().unwrap()).into_owned()
    }
}

/// The kata-owned parent cgroup of `container`, found from the kernel's view.
pub fn cgroup_of(container: &str) -> PathBuf {
    crate::common::cgroup_leaf(container).unwrap_or_else(|| {
        panic!("no kata-owned cgroup for container `{container}` beneath this scope")
    })
}
