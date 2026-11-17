//! An `Egress` capsule on REAL youki, end to end.
//!
//! # What is real here, and the one thing that is not
//!
//! The cells drive `OciStageDriver::drive` — the production composition — so the
//! pinned runtime, the two `createContainer` hooks (`loopback-up` and
//! `hand-listener`), the `SCM_RIGHTS` fd pass from inside the guest's network
//! namespace, the accept on the inherited listener, the allowlist, the refusal
//! records and the proxy teardown are all the real code against a real kernel.
//!
//! The ONE substituted edge is the upstream dial: `OciStageDriver`'s
//! `with_upstream_dial` seam gives the proxy a dialer that connects to a
//! loopback listener this file owns, because every local address is inside the
//! refused set `connect_checked` exists to refuse — and the refused set is
//! proven host-free in `egress_proxy_tests.rs` (its `policy_proxy` cells run the
//! REAL `accept_on`). What the seam preserves is everything the guest side can
//! distinguish: the CONNECT parse, the exact allowlist, the 200/403 answers, and
//! the relayed bytes crossing the namespace boundary on the handed-over fd.
//!
//! # It REFUSES on this host until the profile is installed
//!
//! Same prerequisites as `oci_bundle_live`: the pinned youki, its installed
//! AppArmor profile, a delegated user scope, the fixture closure's store path
//! realised, and `cargo build -p kata-provider-youki -p kata-oci-hook` for the
//! two provider members — all diagnosed in one line by
//! `just _containment-preconditions`. On a host missing any of them the cells
//! FAIL by name rather than skip: the no-skip rule, because a claim with no
//! measurement is a claim kata never made.

#![cfg(target_os = "linux")]

mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use kata_agent::resource_bounds::TeardownOutcome;
use kata_types::error::KataResult;
use kata_types::execution_contract::{
    ArtifactId, ArtifactPrivacy, Capsule, CapsuleBudgets, CapsuleNetwork, CapsuleProcess,
    EgressAuthority, EnvironmentId, GuestAccess, GuestMapping, GuestPath, OccurrenceId,
    PlatformRef, PreparedActionId,
};
use kata_types::nix_environment::{
    ClosureEntry, IntegrityPolicy, NarVerification, NixEnvironmentManifest, Provenance,
    RetentionClass, RetentionIntent, StorePath,
};
use kata_types::primitives::{ContentHash, ObjectId};
use kata_types::sandbox::NetPolicy;
use kata_types::tree_artifact::TreeManifest;
use kata_types::youki_pin::YoukiPin;
use kata_worker::egress_proxy::EgressRefusal;
use kata_worker::execution_route::{ExternalProviderAddress, OciRoute};
use kata_worker::materialize::{BlobSource, StorePathProbe, TreeResolver};
use kata_worker::oci_driver::{
    OCI_PROVIDER_NAME, OciProviderInstallation, OciStageDriver, OciStageRequest,
};
use kata_worker::oci_runtime::certify_youki;
use std::fmt::Write as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// The same real store path every OCI live file names.
const BUSYBOX: &str =
    "/nix/store/qddzvnv6b0805nkvbqddbswddcfhx814-busybox-static-x86_64-unknown-linux-musl-1.37.0";
const BUSYBOX_NAR_HASH: &str = "sha256-d7JNm1d4Wo1oSA2pvoRLt1vqyAhSlIsjE0GckcLiSeA=";
const BUSYBOX_NAR_SIZE: u64 = 1_495_056;

/// The guest proxy port the render fixes — `EGRESS_GUEST_PORT` in the driver. The
/// guest scripts below connect to it literally, which is also the check that the
/// hook bound what the bundle promised.
const GUEST_PORT: u16 = 19200;

/// The marker the guest sends down an opened tunnel and the echo upstream
/// answers back, prefixed — a DERIVED answer, so a mis-wired pipe cannot fake it.
const PING: &[u8] = b"KATA-PING";
const PONG_PREFIX: &[u8] = b"KATA-PONG:";

/// How many upstream dials the seam performed. `fn` pointers cannot capture, so
/// the counter is static — cells read it as a DELTA, never an absolute.
static UPSTREAM_DIALS: AtomicUsize = AtomicUsize::new(0);

fn hash(byte: u8) -> ContentHash {
    ContentHash::new([byte; 32])
}

fn environment() -> NixEnvironmentManifest {
    NixEnvironmentManifest::new(
        "egress-busybox",
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

/// One `Command` capsule carrying `sh -c <script>` under the named network
/// declaration — `Egress { allowlist }` for these cells.
fn capsule(argv: Vec<smol_str::SmolStr>, network: CapsuleNetwork) -> Capsule {
    Capsule::new(
        OccurrenceId(hash(0x6e)),
        PreparedActionId(hash(2)),
        EnvironmentId(hash(3)),
        PlatformRef::new("x86_64-linux", hash(11)).id(),
        vec![
            mapping("/work", 20),
            mapping("/out", 21),
            mapping("/tmp", 22),
        ],
        CapsuleProcess::Command { argv },
        network,
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

fn egress(allowlist: &[(&str, u16)]) -> CapsuleNetwork {
    CapsuleNetwork::Egress {
        allowlist: allowlist
            .iter()
            .map(|(host, port)| EgressAuthority::new(*host, *port).expect("an exact pair"))
            .collect(),
    }
}

/// The live-cell dial: every allowlisted authority maps to the loopback listener
/// this cell owns — the one substitution in an otherwise all-real path, and the
/// only way a live cell CAN have an upstream, since the production policy
/// refuses every local address class by design.
fn loopback_dial(
    _host: &str,
    port: u16,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<tokio::net::TcpStream, EgressRefusal>> + Send + '_>,
> {
    UPSTREAM_DIALS.fetch_add(1, Ordering::SeqCst);
    Box::pin(async move {
        tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .map_err(|error| EgressRefusal::UpstreamUnreachable {
                authority: format!("127.0.0.1:{port}"),
                error: error.to_string(),
            })
    })
}

/// Every mapped tree is EMPTY: these proofs are about the network boundary, and
/// a file in `/work` would be a second thing to be wrong.
struct EmptyTrees;

impl TreeResolver for EmptyTrees {
    fn tree_manifest(&self, _artifact: ArtifactId) -> KataResult<TreeManifest> {
        TreeManifest::new(vec![])
    }

    fn tree_reference(
        &self,
        artifact: ArtifactId,
    ) -> KataResult<kata_types::execution_contract::ArtifactRef> {
        panic!(
            "the driver looked up the reference for tree artifact {artifact:?}; the fixture \
             resolves MANIFESTS only"
        );
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
        panic!("every mapped tree is empty; no member's bytes are read ({object:?})")
    }
}

/// The real host's store, because the container rbinds the closure at its own
/// store path.
struct RealStore;

impl StorePathProbe for RealStore {
    fn present(&self, path: &StorePath) -> KataResult<bool> {
        Ok(Path::new(path.as_str()).is_dir())
    }
}

const INNER_ENV: &str = "KATA_LIVE_EGRESS_DELEGATED_INNER";

/// Run an async `body` inside a delegated user scope — the same shape
/// `interactive_capsule_live.rs` spells it in, for the reason stated there.
fn delegated<F>(test: &'static str, body: F)
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
                 be spawned ({error}). A delegated scope is what lets an unprivileged process \
                 write a cgroup limit — see `just _containment-preconditions`."
            )
        });
    eprintln!(
        "--- delegated inner run of `{test}` stdout ---\n{}\n--- stderr ---\n{}\n---",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    kata_test_utils::delegated_scope::assert_inner_ran_the_one_test(test, &output);
}

/// Locate a workspace binary next to the current test binary.
fn workspace_bin(name: &str) -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let mut cur = exe.parent();
    while let Some(dir) = cur {
        let candidate = dir.join(name);
        if candidate.is_file() {
            common::require_current_provider_protocol("egress rig", name, &candidate);
            return candidate;
        }
        if dir.file_name().and_then(|n| n.to_str()) == Some("target") {
            break;
        }
        cur = dir.parent();
    }
    panic!(
        "`{name}` is not next to the test binary, and it IS the instrument of this proof. `cargo \
         nextest run -p kata-worker` does NOT build it. Run `cargo build -p kata-provider-youki \
         -p kata-oci-hook` in the same command, which is also what keeps a STALE one from being \
         driven."
    );
}

/// The host's `ip` — the `loopback-up` hook execs it by absolute path on the
/// HOST rootfs (a createContainer hook sees the host's mounts inside the guest's
/// netns), so a real iproute2 binary from PATH is the member the provider entry
/// carries here.
fn host_ip() -> PathBuf {
    for candidate in ["/usr/bin/ip", "/usr/sbin/ip", "/bin/ip", "/sbin/ip"] {
        let path = Path::new(candidate);
        if path.is_file() {
            return path.to_path_buf();
        }
    }
    panic!("no iproute2 `ip` on this host — the `loopback-up` hook execs it by absolute path")
}

/// Provision the freshly built provider AND its two egress members into a
/// by-hash store this rig owns: `kata-provider-youki`, `kata-oci-hook` and `ip`,
/// all regular files the entry's content address covers.
fn install_provider(root: &Path) -> OciProviderInstallation {
    let provider = workspace_bin("kata-provider-youki");
    let hook = workspace_bin("kata-oci-hook");
    let source = root.join("provider-src");
    std::fs::create_dir_all(&source).expect("the provider source directory");
    std::fs::copy(
        &provider,
        source.join(format!("kata-provider-{OCI_PROVIDER_NAME}")),
    )
    .expect("the provider bytes copy");
    std::fs::copy(&hook, source.join("kata-oci-hook")).expect("the hook bytes copy");
    std::fs::copy(host_ip(), source.join("ip")).expect("the iproute2 member copies");
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

/// The certified route, or a panic naming the prerequisite this host lacks.
fn route() -> OciRoute {
    let certification = certify_youki(YoukiPin::embedded()).unwrap_or_else(|refusal| {
        panic!(
            "this host cannot deliver the rootless-OCI prerequisite, so there is no container \
             to prove egress through: {refusal}. `just _containment-preconditions` gives the \
             one-line diagnosis."
        )
    });
    assert!(
        Path::new(BUSYBOX).join("bin/busybox").is_file(),
        "the closure's only store object is not realised at {BUSYBOX} — realise it with \
         `nix-store --realise {BUSYBOX}`"
    );
    OciRoute::new(certification)
}

/// Drive one fixture capsule on the real route and return the outcome — the
/// whole of the production path, with the dial seam applied.
async fn drive(
    network: CapsuleNetwork,
    script: String,
) -> (kata_worker::oci_driver::OciStageOutput, tempfile::TempDir) {
    let root = tempfile::tempdir().expect("a temporary worker state root");
    // Unseals the by-hash provider store (`0500`) on every exit: a panic unwinds it
    // before `root`, and a return drops it as `root` moves to the caller, so the
    // caller's `TempDir` can remove the tree. See `kata_worker::UnsealOnDrop`.
    let _unseal = kata_worker::UnsealOnDrop::new(root.path());
    let driver = OciStageDriver::new(
        route(),
        root.path().join("worker-state"),
        install_provider(root.path()),
    )
    .with_upstream_dial(loopback_dial);
    let environment = environment();
    let capsule = capsule(
        vec![
            smol_str::SmolStr::new(format!("{BUSYBOX}/bin/busybox")),
            smol_str::SmolStr::new("sh"),
            smol_str::SmolStr::new("-c"),
            smol_str::SmolStr::new(script),
        ],
        network,
    );
    let output = driver
        .drive(
            "egress-live",
            &OciStageRequest {
                capsule: &capsule,
                environment: &environment,
                network: NetPolicy::Offline,
                trees: &EmptyTrees,
                source: &BytesForbidden,
                probe: &RealStore,
                execution_id: ulid::Ulid::new(),
            },
        )
        .await
        .expect("the egress drive completes");
    (output, root)
}

/// Read a file the guest left in `/out`, named for why its absence fails.
fn guest_wrote(out: &Path, name: &str) -> String {
    std::fs::read_to_string(out.join(name))
        .unwrap_or_else(|error| panic!("the guest did not leave {name} in /out ({error})"))
}

// ---------------------------------------------------------------------------
// The cells
// ---------------------------------------------------------------------------

/// **An allowlisted CONNECT is answered `200` and the tunnel carries bytes in
/// BOTH directions — the guest's `nc` to `127.0.0.1:19200` lands on the WORKER's
/// proxy through the fd the `hand-listener` hook passed out of the namespace.**
///
/// The guest script asks for `upstream.test:<port>`; the dial seam answers at a
/// loopback echo server this cell runs. `/out/proxy.out` must carry the 200 and
/// the derived `KATA-PONG:KATA-PING` — a mis-wired pipe that echoed the request
/// itself would not produce the prefix.
///
/// **Would red if:** the hooks did not run (no listener to accept on — the
/// connect itself fails and `nc` reports refused, not a 403), the allowlist
/// missed an allowed name (a 403 instead of the 200), or the relay moved bytes
/// one way only.
#[test]
#[ignore = "HOST-DEPENDENT — see the module doc. Run with `cargo build -p \
            kata-provider-youki -p kata-oci-hook && cargo nextest run -p kata-worker -P live-smoke \
            -E 'binary(egress_oci_live)' --run-ignored all`."]
fn an_allowlisted_connect_tunnels_through_the_guests_hook_handed_listener_live() {
    delegated(
        "an_allowlisted_connect_tunnels_through_the_guests_hook_handed_listener_live",
        an_allowlisted_connect_body(),
    );
}

async fn an_allowlisted_connect_body() {
    // THE UPSTREAM: one loopback listener that answers PING with PONG:PING —
    // the seam's endpoint, and the thing the guest could never touch without
    // the proxy between.
    let upstream = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("the upstream binds");
    let port = upstream.local_addr().expect("its port").port();
    let server = tokio::spawn(async move {
        let (mut socket, _) = upstream.accept().await.expect("one accepted tunnel");
        let mut buf = vec![0_u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(20), socket.read(&mut buf))
            .await
            .expect("the upstream read inside the tunnel's idle window")
            .expect("a read");
        assert_eq!(
            &buf[..n],
            PING,
            "the upstream saw exactly the guest's bytes, tunnelled verbatim"
        );
        let mut answer = PONG_PREFIX.to_vec();
        answer.extend_from_slice(&buf[..n]);
        socket
            .write_all(&answer)
            .await
            .expect("the answer writes back through the tunnel");
        // Hold briefly so the guest's `nc` reads before the FIN.
        tokio::time::sleep(Duration::from_secs(1)).await;
    });

    let script = format!(
        "{{ printf 'CONNECT upstream.test:{port} HTTP/1.1\\r\\n\\r\\n'; sleep 1; \
         printf '{ping}'; sleep 2; }} | {BUSYBOX}/bin/nc -w 6 127.0.0.1 {GUEST_PORT} \
         > /out/proxy.out 2>/out/proxy.err; true",
        port = port,
        ping = std::str::from_utf8(PING).unwrap(),
    );
    let (output, _root) = drive(egress(&[("upstream.test", port)]), script).await;
    let out = output.attempt_root.path().join("out");
    let seen = guest_wrote(&out, "proxy.out");

    assert!(
        seen.contains("200 Connection established"),
        "the guest read the proxy's own 200 — a CONNECT answer only the worker-side proxy \
         produces. proxy.out: {seen:?}"
    );
    assert!(
        seen.contains(std::str::from_utf8(PONG_PREFIX).unwrap()),
        "the upstream's derived answer came back through the tunnel: {seen:?}"
    );
    let egress = output
        .egress
        .expect("an Egress capsule has an egress outcome");
    assert_eq!(egress.opened_tunnels, 1, "exactly one tunnel opened");
    assert!(
        egress.refusals.is_empty(),
        "an allowed connect records no refusal: {:?}",
        egress.refusals
    );
    assert!(
        egress.relayed_bytes > 0,
        "bytes crossed the namespace boundary on the handed fd"
    );
    server.await.expect("the upstream saw its read");
}

/// **A CONNECT for a host the allowlist does not name is refused `403` +
/// `host_not_allowed`, and the dial seam is never invoked.**
///
/// The recorded refusal is read off `OciStageOutput.egress.refusals` — the same
/// vector `CompletedCapsule.egress_refusals` publishes as durable evidence — and
/// the upstream observation is the `UPSTREAM_DIALS` delta: the refusal happened
/// before any address was resolved or socket opened.
#[test]
#[ignore = "HOST-DEPENDENT — see the module doc."]
fn a_disallowed_host_is_refused_and_records_host_not_allowed_live() {
    delegated(
        "a_disallowed_host_is_refused_and_records_host_not_allowed_live",
        a_disallowed_host_body(),
    );
}

async fn a_disallowed_host_body() {
    let dials_before = UPSTREAM_DIALS.load(Ordering::SeqCst);
    let script = format!(
        "printf 'CONNECT other.test:443 HTTP/1.1\\r\\n\\r\\n' | {BUSYBOX}/bin/nc -w 4 \
         127.0.0.1 {GUEST_PORT} > /out/proxy.out 2>/out/proxy.err; true",
    );
    let (output, _root) = drive(egress(&[("allowed.test", 443)]), script).await;
    let out = output.attempt_root.path().join("out");
    let seen = guest_wrote(&out, "proxy.out");

    assert!(
        seen.contains("403"),
        "the guest reads the refusal as 403: {seen:?}"
    );
    let egress = output.egress.expect("the egress outcome");
    assert!(
        egress.refusals.iter().any(|refusal| matches!(
            refusal,
            EgressRefusal::HostNotAllowed { host, port: 443 } if host == "other.test"
        )),
        "the refusal is recorded by name and authority, and rides into durable evidence: {:?}",
        egress.refusals
    );
    assert_eq!(
        UPSTREAM_DIALS.load(Ordering::SeqCst) - dials_before,
        0,
        "a refused authority never reaches a dial"
    );
    assert_eq!(egress.opened_tunnels, 0, "no tunnel opened for a refusal");
}

/// **The guest's loopback is UP — `loopback-up` ran — and the guest is still a
/// capability-free, seccomp'd process in a netns of its own.**
///
/// The pinned runtime leaves `lo` DOWN (measured under the pin), so `lo` `UP` in
/// `/proc/net/dev` terms is positive evidence
/// the hook ran and is not something the container could have done itself —
/// `CapEff=0` cannot raise an interface. Every observation is the kernel's, read
/// inside the guest and scored on the host.
///
/// **Would red if:** `loopback-up` were not rendered (`lo` reads `DOWN` — the
/// re-measured baseline), the hook's caps leaked to init (`CapEff` non-zero), or
/// the guest shared the host's netns (inode match).
#[test]
#[ignore = "HOST-DEPENDENT — see the module doc."]
fn the_guests_loopback_is_up_and_its_process_stays_capability_free_live() {
    delegated(
        "the_guests_loopback_is_up_and_its_process_stays_capability_free_live",
        the_guests_loopback_body(),
    );
}

async fn the_guests_loopback_body() {
    // No `/sys` in this bundle by design — the flags read goes through the
    // closure's own `ip`, which answers from rtnetlink and needs no capability.
    let script = format!(
        "{BUSYBOX}/bin/busybox ip link show lo > /out/lo-link; \
         {BUSYBOX}/bin/busybox ip addr show lo > /out/lo-addr; \
         cat /proc/net/dev > /out/netdev; \
         grep '^Cap' /proc/self/status > /out/caps; \
         grep '^Seccomp' /proc/self/status > /out/seccomp; \
         readlink /proc/self/ns/net > /out/netns; \
         echo \"proxy-env:$HTTP_PROXY\" > /out/env",
    );
    let (output, _root) = drive(egress(&[("upstream.test", 443)]), script).await;
    let out = output.attempt_root.path().join("out");

    let link = guest_wrote(&out, "lo-link");
    assert!(
        link.contains(",UP"),
        "IFF_UP is set in `<LOOPBACK,UP,LOWER_UP>` — the `loopback-up` hook ran (the pinned \
         runtime's measured baseline is DOWN): {link:?}"
    );
    let addr = guest_wrote(&out, "lo-addr");
    assert!(
        addr.contains("127.0.0.1"),
        "the kernel bound the loopback address when `lo` came up — functional proof the guest's \
         own 127.0.0.1 exists: {addr:?}"
    );
    let netdev = guest_wrote(&out, "netdev");
    let interfaces: Vec<&str> = netdev
        .lines()
        .skip(2)
        .filter_map(|line| line.split(':').next().map(str::trim))
        .collect();
    assert_eq!(
        interfaces,
        vec!["lo"],
        "the guest owns EXACTLY its loopback — the posture is the offline namespace plus the \
         handed listener, and nothing else: {netdev}"
    );
    for cap in ["CapEff", "CapPrm", "CapAmb", "CapBnd"] {
        let caps = guest_wrote(&out, "caps");
        let value = caps
            .lines()
            .find(|row| row.starts_with(cap))
            .and_then(|row| row.split_once('\t').or_else(|| row.split_once(':')))
            .map_or_else(
                || panic!("no {cap} line in {caps}"),
                |(_, value)| value.trim().to_owned(),
            );
        assert!(
            value.chars().all(|c| c == '0'),
            "the guest's capabilities are still empty — the hook's caps were the RUNTIME's, not \
             the init's: {cap}={value}"
        );
    }
    let seccomp = guest_wrote(&out, "seccomp");
    assert!(
        seccomp.contains("Seccomp:\t2") || seccomp.contains("Seccomp: 2"),
        "the seccomp fence is still on under the egress posture: {seccomp}"
    );
    let guest_ns = guest_wrote(&out, "netns").trim().to_owned();
    let host_ns = std::fs::read_link("/proc/self/ns/net")
        .expect("this process's own netns")
        .display()
        .to_string();
    assert_ne!(
        guest_ns, host_ns,
        "the container SHARES the host's netns ({host_ns}); the plan asks for a new one"
    );
    let env = guest_wrote(&out, "env");
    assert!(
        env.contains(&format!("proxy-env:http://127.0.0.1:{GUEST_PORT}")),
        "the plumbing env reached the guest verbatim: {env}"
    );
}

/// **Every proxy spelling a client reads reaches the guest — and a client that
/// reads ONLY the lowercase `http_proxy` reaches the worker's proxy, not a dead
/// route.**
///
/// The environment is read off the kernel (`/proc/self/environ` of the guest's
/// own shell), never off the plan kata rendered. The behavioural half runs
/// busybox `wget`, which — like curl for an `http://` URL — consults only the
/// lowercase `http_proxy`: through the proxy it is answered the proxy's `405`
/// for a non-`CONNECT` request, which busybox reports in its own words;
/// unproxied it resolves the name itself and fails `bad address`, because the
/// guest has no resolver and no route.
///
/// **Would red if:** any of the eight names were not rendered into the
/// container (the environ read), or the lowercase `http_proxy` were absent (wget
/// goes direct and reports `bad address`, not the proxy's `405`).
#[test]
#[ignore = "HOST-DEPENDENT — see the module doc."]
fn every_proxy_spelling_reaches_the_guest_and_lowercase_http_proxy_is_honoured_live() {
    delegated(
        "every_proxy_spelling_reaches_the_guest_and_lowercase_http_proxy_is_honoured_live",
        every_proxy_spelling_body(),
    );
}

async fn every_proxy_spelling_body() {
    let script = format!(
        "{BUSYBOX}/bin/busybox tr '\\000' '\\n' < /proc/self/environ > /out/environ; \
         {BUSYBOX}/bin/busybox wget -q -O /out/body http://upstream.test/ 2> /out/wget-err; \
         echo $? > /out/wget-rc",
    );
    let (output, _root) = drive(egress(&[("upstream.test", 443)]), script).await;
    let out = output.attempt_root.path().join("out");

    let environ = guest_wrote(&out, "environ");
    let proxy = format!("http://127.0.0.1:{GUEST_PORT}");
    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "http_proxy",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        assert!(
            environ
                .lines()
                .any(|line| line == format!("{name}={proxy}")),
            "the guest's own environ carries {name}={proxy}: {environ}"
        );
    }
    for name in ["NO_PROXY", "no_proxy"] {
        assert!(
            environ
                .lines()
                .any(|line| line == format!("{name}=localhost,127.0.0.1,[::1]")),
            "the guest's own environ carries the loopback {name}: {environ}"
        );
    }

    let rc = guest_wrote(&out, "wget-rc");
    let err = guest_wrote(&out, "wget-err");
    assert_ne!(rc.trim(), "0", "the proxy serves no plain GET: {err}");
    assert!(
        err.contains("405") && !err.contains("bad address"),
        "busybox wget, which reads only the lowercase `http_proxy`, reached the worker's proxy \
         and was answered its 405 for a non-CONNECT request — not a direct dial: {err:?}"
    );
}

/// **Teardown leaves nothing behind: no hook process, no handoff socket, no
/// container, no tunnel — scored off `/proc` and the filesystem.**
///
/// The registry verdict on `OciStageOutput.egress.close` is one assertion; the
/// rest are reads kata does not control: `/proc/*/comm` for a surviving
/// `kata-oci-hook`, the attempt root for a surviving socket, `youki list` for a
/// surviving container.
#[test]
#[ignore = "HOST-DEPENDENT — see the module doc."]
fn teardown_leaves_no_hook_process_socket_or_listener_live() {
    delegated(
        "teardown_leaves_no_hook_process_socket_or_listener_live",
        teardown_body(),
    );
}

async fn teardown_body() {
    let script = format!(
        "printf 'CONNECT upstream.test:443 HTTP/1.1\\r\\n\\r\\n' | {BUSYBOX}/bin/nc -w 2 \
         127.0.0.1 {GUEST_PORT} > /out/proxy.out 2>/dev/null; true",
    );
    // The upstream does not exist — `upstream_unreachable` is recorded, the drive
    // still completes, and the teardown questions are identical.
    let (output, _root) = drive(egress(&[("upstream.test", 443)]), script).await;
    let egress = output.egress.expect("the egress outcome");
    assert!(
        matches!(egress.close, TeardownOutcome::Confirmed { .. }),
        "the proxy's teardown is a Confirmed verdict on an observed-empty registry"
    );
    assert!(
        egress
            .refusals
            .iter()
            .any(|r| r.label() == "upstream_unreachable"),
        "the refused connect is the record the teardown rode in on: {:?}",
        egress.refusals
    );

    let attempt = output.attempt_root.path().to_path_buf();
    let tag = "egress-live";
    output.attempt_root.remove(tag, "live cell cleanup");
    assert!(
        !attempt.join("egress").join("handoff.sock").exists(),
        "no handoff socket survives the attempt: {}",
        attempt.join("egress").join("handoff.sock").display()
    );
    assert!(
        !attempt.exists(),
        "the attempt root itself is gone after the caller's remove: {}",
        attempt.display()
    );

    let mut hook_survivors = 0;
    for entry in std::fs::read_dir("/proc").expect("/proc reads") {
        let Ok(entry) = entry else { continue };
        if !entry
            .file_name()
            .to_string_lossy()
            .chars()
            .all(|c| c.is_ascii_digit())
        {
            continue;
        }
        if std::fs::read_to_string(entry.path().join("comm"))
            .is_ok_and(|comm| comm.trim() == "kata-oci-hook")
        {
            hook_survivors += 1;
        }
    }
    assert_eq!(
        hook_survivors, 0,
        "a createContainer hook is scoped to the create phase — a surviving one means the \
         runtime outlived its own hook"
    );
}

/// **A worker death between the listener handoff and the container's work leaves
/// NO ORPHAN LISTENER: the fd dies with the process, and the guest's
/// `/proc/net/tcp` stops listing `127.0.0.1:19200`.**
///
/// The window is the dangerous half of the design — a listener fd that outlived
/// its worker would be a guest endpoint answering to nobody. The claim is that
/// closing is free: the fd is a process's property, and the kernel drops the
/// socket the moment the last fd goes, netns and container alive or not.
///
/// The victim is this same binary re-exec'd: it drives an `Egress` capsule whose
/// command is `sleep`, so the container outlives the crash. The parent watches
/// the CONTAINER's `/proc/<init>/net/tcp` — the netns the socket belongs to —
/// for `0100007F:4B00` (19200) LISTEN to appear, then SIGKILLs the victim and
/// watches the entry VANISH while the container still runs.
#[test]
#[ignore = "HOST-DEPENDENT — see the module doc."]
fn a_worker_death_after_the_handoff_leaves_no_orphan_listener_live() {
    const VICTIM_ENV: &str = "KATA_LIVE_EGRESS_VICTIM";
    const LISTEN_HEX: &str = "0100007F:4B00"; // 127.0.0.1:19200

    if std::env::var(VICTIM_ENV).is_ok() {
        // THE VICTIM — drives the capsule and is SIGKILLed by its parent. The
        // attempt state root is named on the env so the parent can find the
        // container without asking it. A refusal goes to stderr AND a marker
        // file — the parent's assertion cannot see a failure it swallowed.
        let state = std::env::var("KATA_LIVE_EGRESS_STATE").expect("the state root");
        let progress_file = Path::new(&state).join("victim-progress");
        let mark = move |step: &str| {
            let _ = std::fs::write(&progress_file, step);
        };
        mark("alive");
        // Wait for the parent to vacate the scope cgroup: a cgroup holding ANY
        // member process cannot distribute controllers to children (the
        // no-internal-processes rule), and the victim's delegation probe can
        // enable the scope's subtree only once the parent — still a scope
        // member until it runs its own measure — has moved into
        // `kata.supervisor`. Measured: without this ordering the probe's
        // `+memory`/`+pids`/`+cpu` writes are refused EBUSY and the victim's
        // `certify_youki` refuses `cgroup v2 delegation`.
        let clear = Path::new(&state).join("parent-clear");
        let waited = std::time::Instant::now();
        while !clear.exists() {
            assert!(
                waited.elapsed() < Duration::from_secs(30),
                "the parent never vacated the scope cgroup (no parent-clear marker in 30s)"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        mark("parent-clear");
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("the victim's runtime")
            .block_on(async move {
                let root = Path::new(&state);
                let route = route();
                mark("route-certified");
                let provider = install_provider(root);
                mark("provider-installed");
                let driver = OciStageDriver::new(route, root.join("worker-state"), provider)
                    .with_upstream_dial(loopback_dial);
                let environment = environment();
                let capsule = capsule(
                    vec![
                        smol_str::SmolStr::new(format!("{BUSYBOX}/bin/busybox")),
                        smol_str::SmolStr::new("sh"),
                        smol_str::SmolStr::new("-c"),
                        smol_str::SmolStr::new("sleep 120"),
                    ],
                    egress(&[("upstream.test", 443)]),
                );
                mark("driving");
                let outcome = driver
                    .drive(
                        "egress-crash-window",
                        &OciStageRequest {
                            capsule: &capsule,
                            environment: &environment,
                            network: NetPolicy::Offline,
                            trees: &EmptyTrees,
                            source: &BytesForbidden,
                            probe: &RealStore,
                            execution_id: ulid::Ulid::new(),
                        },
                    )
                    .await;
                if let Err(refusal) = &outcome {
                    let text = format!("victim drive refused: {refusal}\n");
                    eprint!("{text}");
                    let _ = std::fs::write(Path::new(&state).join("victim-refusal"), text);
                }
            });
        return;
    }

    // THE PARENT — inside the delegated scope, so the victim's container has
    // somewhere to live. Spawned as a plain child (NOT `delegated`'s scope
    // re-exec: this cell is already inside one).
    delegated(
        "a_worker_death_after_the_handoff_leaves_no_orphan_listener_live",
        async move { a_worker_death_body(VICTIM_ENV, LISTEN_HEX) },
    );
}

// Sync on purpose: the parent half of the cell is a poll-and-kill loop over
// procfs and the filesystem — nothing in it awaits.
fn a_worker_death_body(victim_env: &str, listen_hex: &str) {
    let root = tempfile::tempdir().expect("the crash-window rig root");
    // The victim provisions a sealed (`0500`) provider store under this root; declared
    // AFTER the `TempDir` so it drops BEFORE it. See `kata_worker::UnsealOnDrop`.
    let _unseal = kata_worker::UnsealOnDrop::new(root.path());
    let exe = std::env::current_exe().expect("the test binary's own path");
    // The victim's streams go to FILES — `Stdio::inherit` would land them on a
    // libtest capture buffer a dead process never flushes to anything readable.
    let victim_out =
        std::fs::File::create(root.path().join("victim.stdout")).expect("the victim stdout file");
    let victim_err =
        std::fs::File::create(root.path().join("victim.stderr")).expect("the victim stderr file");
    let mut victim = std::process::Command::new(&exe)
        .args([
            "--exact",
            "a_worker_death_after_the_handoff_leaves_no_orphan_listener_live",
            "--include-ignored",
            "--test-threads",
            "1",
        ])
        .env(victim_env, "1")
        .env("KATA_LIVE_EGRESS_STATE", root.path())
        .env(
            INNER_ENV,
            "a_worker_death_after_the_handoff_leaves_no_orphan_listener_live",
        )
        .stdout(victim_out)
        .stderr(victim_err)
        .spawn()
        .expect("the victim spawns");

    // Vacate THIS cgroup before the victim measures delegation: this inner
    // process is a member of the delegated scope, and a cgroup with members
    // cannot enable controllers for its children. `cgroup_delegation()`'s own
    // measure relocates this process into `kata.supervisor` — the refusal it
    // reports here (the victim still occupies the scope when it probes) is
    // EXPECTED and ignored: the move is the point, not the verdict.
    let _ = kata_worker::sandbox_bounds::cgroup_delegation();
    std::fs::write(root.path().join("parent-clear"), b"").expect("the parent-clear marker");

    // Find the container's init pid via the pinned runtime's OWN view of the
    // state root under the victim's attempt directory. `youki --root` for the
    // provider is `<attempt>/oci/<container-id>/state` — materialize() puts the
    // bundle and the runtime state beneath one per-container home.
    let oci_root = root
        .path()
        .join("worker-state")
        .join("attempts")
        .join("egress-crash-window")
        .join("oci");
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    let mut found = None;
    let mut watch_notes = String::new();
    while std::time::Instant::now() < deadline {
        let homes: Vec<PathBuf> = std::fs::read_dir(&oci_root)
            .map(|dir| {
                dir.flatten()
                    .map(|entry| entry.path())
                    .filter(|path| path.is_dir())
                    .collect()
            })
            .unwrap_or_default();
        let state_root = homes.first().map(|home| home.join("state"));
        if let Some(state_root) = state_root {
            let list = std::process::Command::new(YoukiPin::embedded().store_path())
                .arg("--root")
                .arg(&state_root)
                .arg("list")
                .output()
                .expect("the pinned runtime lists");
            let text = String::from_utf8_lossy(&list.stdout);
            let _ = writeln!(
                watch_notes,
                "state_root={} youki-list={:?}",
                state_root.display(),
                text.trim()
            );
            if let Some((id, pid)) = parse_list_id_pid(&text) {
                let tcp =
                    std::fs::read_to_string(format!("/proc/{pid}/net/tcp")).unwrap_or_default();
                if tcp
                    .lines()
                    .any(|line| line.contains(listen_hex) && line.contains(" 0A "))
                {
                    found = Some((id, pid, state_root));
                    break;
                }
            }
        } else {
            let _ = writeln!(
                watch_notes,
                "oci_root={} exists={} homes={:?}",
                oci_root.display(),
                oci_root.exists(),
                homes
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let _ = std::fs::write(root.path().join("watch-notes"), &watch_notes);
    let (container_id, init_pid, state_root) = found.unwrap_or_else(|| {
        let _ = victim.kill();
        let _ = victim.wait();
        let refusal = std::fs::read_to_string(root.path().join("victim-refusal"))
            .unwrap_or_else(|_| "(no victim-refusal marker)".to_owned());
        let progress = std::fs::read_to_string(root.path().join("victim-progress"))
            .unwrap_or_else(|_| "(no victim-progress marker)".to_owned());
        let victim_err = std::fs::read_to_string(root.path().join("victim.stderr"))
            .unwrap_or_else(|_| "(unreadable)".to_owned());
        let victim_out = std::fs::read_to_string(root.path().join("victim.stdout"))
            .unwrap_or_else(|_| "(unreadable)".to_owned());
        panic!(
            "no `0100007F:4B00` LISTEN entry in the container's netns within 90s — either the \
             handoff never happened or this read is looking at the wrong truth. victim progress: \
             {progress}; victim's own report: {refusal}; victim stdout: {victim_out}; victim \
             stderr: {victim_err}; watcher saw: {}",
            watch_notes
                .lines()
                .rev()
                .take(12)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("\n")
        )
    });

    // SIGKILL — not a graceful stop. The claim under test is the KERNEL's: the
    // fd closes because its owner is dead, not because anyone remembered to.
    victim.kill().expect("SIGKILL the victim");
    let _ = victim.wait();

    let tcp_path = format!("/proc/{init_pid}/net/tcp");
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let vanished = loop {
        let tcp = std::fs::read_to_string(&tcp_path).unwrap_or_default();
        if !tcp
            .lines()
            .any(|line| line.contains(listen_hex) && line.contains(" 0A "))
        {
            break true;
        }
        if std::time::Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(100));
    };

    // The container still runs — the listener died with the worker, not with the
    // guest. Clean up: KILL it through the pinned runtime, on the attempt's own
    // state root.
    let _ = std::process::Command::new(YoukiPin::embedded().store_path())
        .arg("--root")
        .arg(&state_root)
        .args(["kill", "--all", &container_id, "KILL"])
        .status();
    let _ = std::process::Command::new(YoukiPin::embedded().store_path())
        .arg("--root")
        .arg(&state_root)
        .args(["delete", "--force", &container_id])
        .status();

    assert!(
        vanished,
        "the listener fd outlived the worker that owned it — `/proc/{init_pid}/net/tcp` still \
         lists a 19200 LISTEN 15s after the SIGKILL: the orphan listener the design exists to \
         make impossible"
    );
}

/// The `(id, pid)` of the first container `youki list` names — the runtime's own
/// view of the state root, not kata's. `youki list` prints a TABLE (its
/// `--format` admits only `default`/`table`): an `ID PID STATUS …` header, then
/// one whitespace-separated row per container.
fn parse_list_id_pid(list: &str) -> Option<(String, i32)> {
    let row = list
        .lines()
        .find(|line| !line.starts_with("ID") && !line.trim().is_empty())?;
    let mut columns = row.split_whitespace();
    let id = columns.next()?.to_owned();
    let pid = columns.next()?.parse().ok()?;
    Some((id, pid))
}
