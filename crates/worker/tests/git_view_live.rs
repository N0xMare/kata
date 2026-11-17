//! The git view's LIVE containment proof: the `/work` git view, observed
//! INSIDE a real rootless-youki container by a real `git`, and read back on the
//! host afterwards.
//!
//! # The claim under test
//!
//! `git_view.rs`'s host-free cells prove the materialized layout answers
//! `status`/`log`/`commit`/`push`-refusal on the host, and
//! `vcs/tests/git_view.rs` proves the producer's artifact assembles a real
//! repository. Neither proves the mounts carry it across the namespace
//! boundary: this cell runs the WHOLE chain — host repo → jj adoption → the
//! real producer's history artifact → CAS → `materialize` → `BundleMounts` →
//! `spec_for` → youki → the guest's own git → `scratch_commits` evidence →
//! `publish_work_delta` — and lets the guest's verdicts grade it.
//!
//! # Why `#[ignore]`d
//!
//! Same reason `oci_bundle_live.rs` states at length: the cell needs the
//! pinned youki, its installed AppArmor profile, a delegated user scope and
//! the fixture closure's store paths realised — facts `just gate` must not
//! require, so it rides the containment lane's `oci-live-smoke` step, which
//! selects `binary(git_view_live)`. It never probes-and-skips: a host that
//! cannot deliver rootless OCI FAILS here, and the panic names what refused.
//!
//! # The environment is the store's own answer
//!
//! The guest needs a real `git`, so the environment is `git-minimal`'s WHOLE
//! closure — `nix-store -q --requisites` supplies the path list and
//! `nix path-info --json` the `narHash`/`narSize`/`references` the manifest
//! records. One path is PINNED ([`GIT_MINIMAL`]) the way `oci_bundle_live.rs`
//! pins `BUSYBOX`: realised by hand, unrooted on purpose, so `nix-store --gc`
//! is a red rather than a stale pass.

#![cfg(target_os = "linux")]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use kata_core::store::CasStore;
use kata_effects_contract::{ExecutionWorkspaceKey, ExecutionWorkspaceProvider};
use kata_test_utils::git::{hermetic_git_in, init_git_repo_at, run_git};
use kata_types::agent::AdapterKind;
use kata_types::execution_contract::{
    AgentTurnSpec, ArtifactId, ArtifactPrivacy, ArtifactRef, Capsule, CapsuleBudgets,
    CapsuleGitView, CapsuleNetwork, CapsuleProcess, EnvironmentId, GitIdentity, GuestAccess,
    GuestMapping, GuestPath, OccurrenceId, PlatformRef, PreparedActionId,
};
use kata_types::nix_environment::{
    ClosureEntry, IntegrityPolicy, NarVerification, NixEnvironmentManifest, Provenance,
    RetentionClass, RetentionIntent, StorePath,
};
use kata_types::primitives::ContentHash;
use kata_types::sandbox::NetPolicy;
use kata_types::tree_artifact::{
    CommittedBaseGitView, TreeEntry, TreeEntryMode, TreeManifest, TreeNode, TreePath,
};
use kata_types::tree_delta::{TreeChangeKind, TreeDelta};
use kata_types::youki_pin::YoukiPin;
use kata_vcs::{JjBackend, VcsBackend};
use kata_worker::git_view::scratch_commits;
use kata_worker::materialize::{
    DeclaredTreeResolver, LocalCasBlobSource, LocalStorePathProbe, materialize,
};
use kata_worker::oci_bundle::{BundleMounts, materialize_bundle, spec_for};
use kata_worker::oci_cgroup::{AttemptContainment, OciParentCgroup};
use kata_worker::result_publication::CasBlobSink;
use kata_worker::work_delta::publish_work_delta;
use smol_str::SmolStr;
use ulid::Ulid;

/// The guest's `git` — `git-minimal`, not the full `git`: the minimal build's
/// closure is a third of full git's (no perl tree), and every command this
/// cell's script runs is POSIX `sh` builtins + `git`, which is exactly what
/// minimal is for.
const GIT_MINIMAL: &str = "/nix/store/mkwrimym2n8jcx536g22f5qv74ggfccc-git-minimal-2.54.0";

/// Generous: the guest runs a dozen git invocations, nothing more.
const BUDGET: Duration = Duration::from_secs(60);

/// Marks the re-exec'd inner run — the same delegated-scope dance
/// `oci_bundle_live.rs` performs, re-spelled per its own rule about not
/// sharing what a delegated scope IS.
const INNER_ENV: &str = "KATA_GIT_VIEW_DELEGATED_INNER";

fn hash(byte: u8) -> ContentHash {
    ContentHash::new([byte; 32])
}

// ---------------------------------------------------------------------------
// The fixture repository — real commits, an unreachable host object, and a
// `.gitignore` the delta scan must honor.
// ---------------------------------------------------------------------------

/// What the fixture hands the assertions: the committed base, a host-only
/// object, and the `.git` content listing taken AFTER the jj workspace exists
/// — the producer-and-guest window must leave it byte-identical (the
/// workspace's own jj bookkeeping legitimately precedes the snapshot).
struct Repo {
    base: String,
    unreachable: String,
    store_listing: String,
    /// The trunk target the workspace forked from and the producer reads.
    target: kata_types::target::ExecutionTarget,
}

/// `find` + `sha256sum` over `.git/objects`, plus `show-ref` — read with tools
/// that share no code with kata, so a producer-side write would show here.
fn git_store_listing(repo: &Path) -> String {
    let mut paths: Vec<String> = String::from_utf8(
        Command::new("find")
            .arg(repo.join(".git/objects"))
            .args(["-type", "f"])
            .output()
            .expect("find runs")
            .stdout,
    )
    .expect("utf8")
    .lines()
    .map(str::to_owned)
    .collect();
    paths.sort();
    let mut listing = String::new();
    for path in paths {
        listing.push_str(
            &String::from_utf8(
                Command::new("sha256sum")
                    .arg(&path)
                    .output()
                    .expect("sha256sum runs")
                    .stdout,
            )
            .expect("utf8"),
        );
    }
    listing.push_str(
        &String::from_utf8(
            hermetic_git_in(repo)
                .arg("show-ref")
                .output()
                .expect("show-ref runs")
                .stdout,
        )
        .expect("utf8"),
    );
    listing
}

/// A `git hash-object -w` over piped bytes — the host-only object the view
/// must NOT carry, spelled the way `vcs/tests/git_view.rs` spells it.
fn hash_object(repo: &Path, bytes: &[u8]) -> String {
    let mut child = hermetic_git_in(repo)
        .args(["hash-object", "-w", "--stdin"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("hash-object spawns");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(bytes)
        .expect("write");
    let out = child.wait_with_output().expect("wait");
    assert!(out.status.success(), "hash-object: {out:?}");
    String::from_utf8(out.stdout)
        .expect("utf8")
        .trim()
        .to_owned()
}

/// Three commits on `main` plus the seed (`file.txt` evolving, `src/main.rs`
/// static, `.gitignore` naming `scratch/`), one host-only blob — then jj
/// adoption and one execution workspace, so the producer packs the REAL
/// committed base.
fn fixture_repo(
    root: &Path,
) -> (
    PathBuf,
    JjBackend,
    kata_effects_contract::ExecutionWorkspaceHandle,
    Repo,
) {
    let repo = root.join("project");
    std::fs::create_dir_all(&repo).expect("repo dir");
    init_git_repo_at(&repo);
    std::fs::write(repo.join(".gitignore"), b"scratch/\n").expect("gitignore");
    std::fs::write(repo.join("file.txt"), b"one\n").expect("file.txt");
    std::fs::create_dir(repo.join("src")).expect("src dir");
    std::fs::write(repo.join("src/main.rs"), b"fn main() {}\n").expect("main.rs");
    run_git(&repo, &["add", "-A"]);
    run_git(&repo, &["commit", "-qm", "first"]);
    std::fs::write(repo.join("file.txt"), b"one\ntwo\n").expect("file.txt");
    run_git(&repo, &["commit", "-qam", "second"]);
    std::fs::write(repo.join("file.txt"), b"one\ntwo\nthree\n").expect("file.txt");
    run_git(&repo, &["commit", "-qam", "third"]);
    let unreachable = hash_object(&repo, b"a host-only object\n");

    let backend = JjBackend::open(&repo).expect("adopt the colocated repo");
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let target = kata_vcs::test_support::resolve_trunk_target(&backend, &key)
        .expect("resolve the trunk target");
    let handle = ExecutionWorkspaceProvider::create_workspace(&backend, &key, &target)
        .expect("the execution workspace forks off the trunk target");
    let base = String::from_utf8(
        hermetic_git_in(&repo)
            .args(["rev-parse", "main"])
            .output()
            .expect("rev-parse runs")
            .stdout,
    )
    .expect("utf8")
    .trim()
    .to_owned();
    let store_listing = git_store_listing(&repo);
    (
        repo,
        backend,
        handle,
        Repo {
            base,
            unreachable,
            store_listing,
            target,
        },
    )
}

// ---------------------------------------------------------------------------
// The CAS — members stream in as the producer emits them, the manifest last.
// ---------------------------------------------------------------------------

/// Produce the history artifact through the REAL `kata-vcs` producer, keeping
/// every streamed member in `cas`, and return `(history ArtifactRef, view
/// metadata)` — the publish shape `publish_execution_git_view` runs on main,
/// reproduced worker-side so the cell owns no operational.db.
fn produce_history(
    cas: &CasStore,
    backend: &JjBackend,
    handle: &kata_effects_contract::ExecutionWorkspaceHandle,
    target: &kata_types::target::ExecutionTarget,
) -> (ArtifactRef, CommittedBaseGitView) {
    let view = ExecutionWorkspaceProvider::committed_base_git_history(
        backend,
        handle,
        target,
        None,
        u64::MAX,
        &mut |bytes| Ok(cas.put_durable(bytes)?.object_id()),
    )
    .expect("the producer packs the committed base");
    let receipt = cas
        .put_durable(&view.manifest_bytes)
        .expect("the manifest holds");
    (
        ArtifactRef::new(receipt.object_id(), receipt.size(), ArtifactPrivacy::Public),
        view,
    )
}

/// One `TreeEntry` for bytes put in the CAS.
fn member(cas: &CasStore, path: &str, bytes: &[u8]) -> TreeEntry {
    let receipt = cas.put_durable(bytes).expect("member holds");
    TreeEntry {
        path: TreePath::new(path).expect("a tree path"),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object: receipt.object_id(),
            size_bytes: receipt.size(),
        },
    }
}

fn tree_ref(cas: &CasStore, entries: Vec<TreeEntry>) -> ArtifactRef {
    let manifest = TreeManifest::new(entries).expect("a manifest");
    let receipt = cas
        .put_durable(&manifest.manifest_bytes().expect("manifest bytes"))
        .expect("the manifest holds");
    ArtifactRef::new(receipt.object_id(), receipt.size(), ArtifactPrivacy::Public)
}

/// The `/work` tree — the fixture's tracked content, including its
/// `.gitignore`, exactly as committed.
fn work_tree(cas: &CasStore) -> ArtifactRef {
    tree_ref(
        cas,
        vec![
            member(cas, ".gitignore", b"scratch/\n"),
            member(cas, "README.md", b"seed\n"),
            member(cas, "file.txt", b"one\ntwo\nthree\n"),
            member(cas, "src/main.rs", b"fn main() {}\n"),
        ],
    )
}

// ---------------------------------------------------------------------------
// The environment — `git-minimal`'s whole closure, read off the store.
// ---------------------------------------------------------------------------

/// `nix path-info --json`'s per-path record — the fields `ClosureEntry` needs.
#[derive(serde::Deserialize)]
struct PathInfo {
    #[serde(rename = "narHash")]
    nar_hash: String,
    #[serde(rename = "narSize")]
    nar_size: u64,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    ca: Option<String>,
}

/// The environment manifest over `git-minimal`'s full requisite closure —
/// every store path the guest's `git` can need, each becoming its own `ro`
/// bind. `references` arrive as names in `nix`'s answer and resolve to indices
/// into the supplied list; the constructor remaps them through its sort.
/// Returns the manifest and the absolute store path of a POSIX shell the
/// closure carries, which the script argv leads with.
fn git_environment() -> (NixEnvironmentManifest, String) {
    let realised = String::from_utf8(
        Command::new("nix-store")
            .args(["-q", "--requisites", GIT_MINIMAL])
            .output()
            .expect("nix-store runs — a host without nix cannot build this environment")
            .stdout,
    )
    .expect("utf8");
    let paths: Vec<String> = realised.lines().map(str::to_owned).collect();
    assert!(
        paths.iter().any(|path| path == GIT_MINIMAL),
        "the store's requisites do not contain their own query root {GIT_MINIMAL}"
    );
    let absent: Vec<&String> = paths
        .iter()
        .filter(|path| !Path::new(path).exists())
        .collect();
    assert!(
        absent.is_empty(),
        "the git environment's closure is not realised: {absent:?}. Realise it with \
         `nix-store --realise {GIT_MINIMAL}` — the cell inherits the store's answer \
         and refuses when there is none."
    );
    let info_json = String::from_utf8(
        Command::new("nix")
            .arg("path-info")
            .arg("--json")
            .args(&paths)
            .output()
            .expect("nix path-info runs")
            .stdout,
    )
    .expect("utf8");
    let info: std::collections::BTreeMap<String, PathInfo> =
        serde_json::from_str(&info_json).expect("path-info is json");
    let index = |name: &str| -> u32 {
        paths
            .iter()
            .position(|path| path == name)
            .unwrap_or_else(|| panic!("{name} is a reference but not a requisite"))
            .try_into()
            .expect("the closure fits in u32")
    };
    let closure: Vec<ClosureEntry> = paths
        .iter()
        .map(|path| {
            let entry = info
                .get(path)
                .unwrap_or_else(|| panic!("{path} in path-info"));
            let mut references: Vec<u32> =
                entry.references.iter().map(|name| index(name)).collect();
            references.retain(|i| *i != index(path));
            references.sort_unstable();
            references.dedup();
            ClosureEntry {
                store_path: StorePath::new(path).expect("a store path"),
                nar_hash: SmolStr::new(entry.nar_hash.as_str()),
                nar_size: entry.nar_size,
                references,
                ca: entry.ca.as_deref().map(SmolStr::new),
            }
        })
        .collect();

    // The interpreter the script argv leads with — a shell the closure itself
    // carries, found by its binary rather than guessed by name.
    let shell = paths
        .iter()
        .map(|path| PathBuf::from(path).join("bin/sh"))
        .find(|sh| sh.is_file())
        .or_else(|| {
            paths
                .iter()
                .map(|path| PathBuf::from(path).join("bin/bash"))
                .find(|bash| bash.is_file())
        })
        .expect("the git closure carries a POSIX shell the script can exec");
    let shell_dir = shell
        .parent()
        .expect("the shell has a parent")
        .display()
        .to_string();
    // `cat`, `mkdir` and `touch` in the script are coreutils — also a closure
    // requisite, found by `bin/cat` rather than a name pattern.
    let coreutils_bin = paths
        .iter()
        .map(|path| PathBuf::from(path).join("bin"))
        .find(|bin| bin.join("cat").is_file() && bin.join("mkdir").is_file())
        .expect("the git closure carries coreutils the script can exec")
        .display()
        .to_string();

    let manifest = NixEnvironmentManifest::new(
        "git-view-live",
        PlatformRef::new("x86_64-linux", hash(11)),
        Provenance::StorePaths {
            nixpkgs_attribute: "nixpkgs#gitMinimal".into(),
        },
        vec![StorePath::new(GIT_MINIMAL).expect("the pinned git store path")],
        closure,
        vec![
            GuestPath::new(format!("{GIT_MINIMAL}/bin")).expect("git's bin under the closure"),
            GuestPath::new(coreutils_bin).expect("coreutils' bin under the closure"),
            GuestPath::new(shell_dir).expect("the shell's bin under the closure"),
        ],
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
    .expect("the git environment is well formed");
    (manifest, shell.display().to_string())
}

// ---------------------------------------------------------------------------
// The capsule — `CapsuleProcess::Agent` is the only arm `git_view` admits.
// The turn's kind fixes what the container runs; this rig's placement runs a
// scripted git harness instead: the claim is the VIEW, not the harness.
// ---------------------------------------------------------------------------

/// The guest-side script — every verdict lands in `/out` for the host to
/// grade. `git` resolves through the manifest's `path_prepend`; each check
/// writes its own file so one red line names its own claim rather than
/// aborting the evidence set.
fn guest_script(unreachable: &str) -> String {
    format!(
        "cd /work\n\
         git status --porcelain > /out/status.txt 2>&1\n\
         git log --format=%s > /out/log.txt 2>&1\n\
         git blame --line-porcelain -- file.txt > /out/blame.txt 2>&1\n\
         cat /work/.git > /out/gitfile.txt 2>&1\n\
         git cat-file -t {unreachable} > /dev/null 2>&1 && echo PRESENT > /out/unreachable.txt \
            || echo ABSENT > /out/unreachable.txt\n\
         printf 'guest line\\n' >> file.txt\n\
         mkdir -p scratch && printf 'ignored\\n' > scratch/noise.txt\n\
         printf 'new\\n' > added.txt\n\
         git add -A && git commit -q -m \"the guest's own commit\"\n\
         git rev-parse HEAD > /out/tip.txt 2>&1\n\
         git push > /out/push.txt 2>&1 || printf 'push refused\\n' >> /out/push.txt\n\
         touch /git-history/forbidden 2>/dev/null && echo WRITABLE > /out/history-ro.txt \
            || echo readonly > /out/history-ro.txt\n\
         git status --porcelain > /out/status-after.txt 2>&1\n"
    )
}

// ---------------------------------------------------------------------------
// The staged run — the same launch seam oci_bundle_live exercises.
// ---------------------------------------------------------------------------

fn delegated(test: &'static str, body: fn()) {
    if std::env::var(INNER_ENV).as_deref() == Ok(test) {
        return body();
    }
    let exe = std::env::current_exe().expect("the test binary's own path");
    let output = Command::new("systemd-run")
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
                 create the parent cgroup kata places this container under — see \
                 `just _containment-preconditions`."
            )
        });
    eprintln!(
        "--- delegated inner run of `{test}` stdout ---\n{}\n--- stderr ---\n{}\n---",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    kata_test_utils::delegated_scope::assert_inner_ran_the_one_test(test, &output);
}

/// The whole produce → materialize → plan → launch → evidence-read chain.
fn live_body() {
    let root = tempfile::Builder::new()
        .prefix("kata-git-view-live-")
        .tempdir()
        .expect("the staging tempdir");
    let cas = CasStore::open(root.path().join("cas.db"), root.path().join("cas"))
        .expect("a fresh CAS opens");
    let (repo, backend, handle, fixture) = fixture_repo(root.path());
    let (history, view_meta) = produce_history(&cas, &backend, &handle, &fixture.target);
    let work = work_tree(&cas);
    let empty = tree_ref(&cas, Vec::new());

    let (environment, shell) = git_environment();
    let view = CapsuleGitView {
        history: history.clone(),
        base_commit: SmolStr::new(fixture.base.as_str()),
        branch: view_meta.branch.clone(),
        identity: GitIdentity {
            name: view_meta.identity.name.clone(),
            email: view_meta.identity.email.clone(),
        },
    };
    let script = guest_script(&fixture.unreachable);
    let mapping = |guest: &str, artifact: ArtifactId| GuestMapping {
        artifact,
        guest_path: GuestPath::new(guest).expect("a guest path"),
        access: GuestAccess::ReadWrite,
    };
    let capsule = Capsule::new(
        OccurrenceId(hash(1)),
        PreparedActionId(hash(2)),
        EnvironmentId(hash(3)),
        PlatformRef::new("x86_64-linux", hash(11)).id(),
        vec![
            mapping("/work", work.id()),
            mapping("/out", empty.id()),
            mapping("/tmp", empty.id()),
        ],
        CapsuleProcess::Agent(AgentTurnSpec {
            adapter: AdapterKind::NanocodeOpenai,
            model: None,
            reasoning_effort: None,
            output_schema: None,
            prompt: ArtifactId(hash(9)),
            credential: None,
            env: std::collections::BTreeMap::new(),
        }),
        CapsuleNetwork::Offline,
        Some(view.clone()),
        CapsuleBudgets {
            wall_time_ms: 60_000,
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
    .expect("the git-view live capsule is well formed");

    // The agent capsule's init is `/.kata/kata-toolhost`, fixed by kata: the
    // guest script stands in for it — a `#!` script over the closure's own
    // shell, in the directory the bundle binds read-only at `/.kata` — so the
    // guest's git runs as the capsule's init would run a tool.
    let toolhost = root.path().join("toolhost");
    std::fs::create_dir_all(&toolhost).expect("the stand-in toolhost directory");
    let init = toolhost.join("kata-toolhost");
    std::fs::write(&init, format!("#!{shell}\n{script}")).expect("the stand-in init writes");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&init, std::fs::Permissions::from_mode(0o755))
            .expect("the stand-in init is executable");
    }
    let attempt_root = root.path().join("attempt");
    let mounts = BundleMounts::under(&attempt_root, 16 * 1024 * 1024)
        .expect("an absolute attempt root with a non-zero /tmp size")
        .with_git_view()
        .with_toolhost(toolhost)
        .expect("an absolute toolhost directory");
    std::fs::create_dir_all(&attempt_root).expect("the attempt root");

    // THE MATERIALIZER — production code lays out work/out/git-history/git and
    // the /work/.git gitfile.
    let source =
        LocalCasBlobSource::open(&root.path().join("cas.db"), &root.path().join("cas")).unwrap();
    let trees =
        DeclaredTreeResolver::new(vec![history.clone(), work.clone(), empty.clone()], &source);
    let execution = Ulid::new();
    let attempt = Ulid::new();
    let roots = materialize(
        &capsule,
        &environment,
        &trees,
        &source,
        &LocalStorePathProbe,
        &attempt_root,
        execution,
    )
    .expect("the git view materializes");
    let layout = roots.git_view.as_ref().expect("the roots carry the view");
    assert_eq!(layout.history, attempt_root.join("git-history"));
    assert_eq!(layout.scratch, attempt_root.join("git"));

    // The kata-owned parent cgroup, under this host's measured delegation.
    let delegation = kata_worker::sandbox_bounds::cgroup_delegation();
    let usable = delegation.usable_parent.as_deref().unwrap_or_else(|| {
        panic!(
            "this host delegates no cgroup kata may create a child under: {evidence}",
            evidence = delegation.evidence
        )
    });
    let sweep_root = usable.join(format!("kata.git-view-live.{}", std::process::id()));
    std::fs::create_dir_all(&sweep_root).expect("the rig's own sweep root");
    for controller in kata_worker::sandbox_bounds::capsule_subtree_controllers(delegation) {
        let _ = std::fs::write(
            sweep_root.join("cgroup.subtree_control"),
            format!("+{}", controller.token()),
        );
    }
    let container_id = format!("kata-{}", capsule.id().0);
    let parent =
        OciParentCgroup::establish(&sweep_root, &container_id, delegation, &capsule.budgets())
            .expect("the kata-owned parent cgroup establishes");
    let containment =
        AttemptContainment::new(parent.path().to_path_buf(), attempt_root.join("oci"))
            .expect("the containment record");
    let plan = spec_for(
        &capsule,
        &environment,
        &mounts,
        &containment,
        NetPolicy::Offline,
        None,
    )
    .expect("the git-view capsule plans");
    let bundle = root.path().join("bundle");
    materialize_bundle(&plan, &bundle).expect("the bundle writes");

    let pin = YoukiPin::embedded();
    let observed = kata_worker::oci_runtime::run_bundle(
        Path::new(pin.store_path()),
        &bundle,
        bundle.parent().expect("the bundle has a parent"),
        &plan.container_id,
        BUDGET,
    )
    .unwrap_or_else(|error| {
        panic!(
            "the delegated-scope launch could not run ({error}). A host without the pinned youki \
             at {path}, without its installed AppArmor profile, or without `systemd-run --user` \
             cannot deliver rootless OCI — `just _containment-preconditions` diagnoses it in one \
             line. There is no skip here on purpose.",
            path = pin.store_path(),
        )
    });
    eprintln!(
        "--- container stdout ---\n{}\n--- stderr ---\n{}",
        observed.stdout, observed.stderr
    );
    assert_eq!(
        observed.exit.as_deref(),
        Some("0"),
        "the guest script exits 0"
    );

    // ── The guest's own verdicts, read off the host's /out ──────────────
    let out = mounts.out().to_path_buf();
    let read = |name: &str| -> String {
        std::fs::read_to_string(out.join(name))
            .unwrap_or_else(|e| panic!("/out/{name} was not written ({e}) — the guest's own file"))
    };
    assert_eq!(
        read("status.txt").trim(),
        "",
        "a freshly materialized view is clean"
    );
    assert_eq!(
        read("log.txt").trim(),
        "third\nsecond\nfirst\nseed",
        "real reachable history from the committed base — the fixture's own subjects"
    );
    assert!(
        read("blame.txt").contains("author "),
        "blame answers through the alternates"
    );
    assert_eq!(
        read("gitfile.txt").trim(),
        "gitdir: /git",
        "/work/.git is the gitfile, nothing else"
    );
    assert_eq!(
        read("unreachable.txt").trim(),
        "ABSENT",
        "the host-only object did not cross the mount boundary"
    );
    let tip = read("tip.txt").trim().to_owned();
    assert_ne!(tip, fixture.base, "the guest's commit is a NEW commit");
    assert!(
        read("push.txt").contains("No configured push destination"),
        "push is refused by the repository's shape: {}",
        read("push.txt")
    );
    assert_eq!(
        read("history-ro.txt").trim(),
        "readonly",
        "the guest's own touch on /git-history is refused by the mount"
    );
    assert_eq!(
        read("status-after.txt").trim(),
        "",
        "after `git add -A && git commit` the tree is clean — the guest's own \
         .gitignore kept `scratch/` out of the commit"
    );

    // ── Host-side, after the container is gone ───────────────────────────
    // The producer and the guest between them never touched the host store:
    // same objects, same refs, byte for byte.
    assert_eq!(
        git_store_listing(&repo),
        fixture.store_listing,
        "the host repository is byte-identical — the view is a COPY"
    );
    // The scratch evidence names exactly the guest's commit, parented on the
    // base, with the inherited identity.
    let commits = scratch_commits(
        &attempt_root,
        execution,
        attempt,
        capsule
            .git_view()
            .expect("the capsule carries its git view"),
        &kata_types::redaction::LiftedSecrets::none(),
    )
    .expect("the scratch repository reports");
    assert_eq!(commits.len(), 1, "{commits:?}");
    assert_eq!(commits[0].commit, tip, "the report names the guest's tip");
    assert_eq!(commits[0].subject, "`the guest's own commit`");
    assert_eq!(commits[0].parents, vec![fixture.base.clone()]);
    assert_eq!(
        commits[0].author_name,
        kata_types::redaction::elide(&view_meta.identity.name)
    );

    // The /work delta: `.git` absent even though it exists on disk, `scratch/`
    // absent because the tree's own .gitignore names it, `file.txt` written,
    // `added.txt` new.
    let sink = CasBlobSink(&cas);
    let published = publish_work_delta(
        mounts.work(),
        work.id(),
        &trees,
        capsule.budgets(),
        &sink,
        roots.work_snapshot.as_ref(),
        None,
    )
    .expect("the /work delta publishes");
    let delta_bytes = cas
        .get_verified(
            &published.object_id(),
            published.size_bytes(),
            TreeDelta::MAXIMUM_ENCODED_BYTES,
        )
        .expect("the delta verifies out of the store");
    let delta: TreeDelta =
        serde_json::from_slice(&delta_bytes).expect("the bytes decode as a delta");
    let paths: Vec<&str> = delta
        .changes()
        .iter()
        .map(|change| change.path.as_str())
        .collect();
    assert!(
        !paths
            .iter()
            .any(|path| path == &".git" || path.starts_with(".git/")),
        "the gitfile never reaches the delta: {paths:?}"
    );
    assert!(
        !paths.iter().any(|path| path.starts_with("scratch/")),
        "the ignored directory is omitted: {paths:?}"
    );
    assert!(
        paths.contains(&"added.txt"),
        "the guest's new file is in the delta: {paths:?}"
    );
    assert!(
        delta.changes().iter().any(|change| {
            change.path.as_str() == "file.txt"
                && matches!(&change.change, TreeChangeKind::Write { .. })
        }),
        "the guest's edit is a write: {paths:?}"
    );
}

/// **The git view's whole promise, inside a real container.**
///
/// An agent capsule's `/work` is a normal, writable, disposable git repository
/// with real reachable history: the guest's `git` reports a clean tree,
/// walks the committed base's history, blames through the read-only history
/// mount, commits its own work to the scratch store, is refused a push by
/// repository shape (no remote), and cannot touch `/git-history` or a host
/// object the base never reached. After teardown, `scratch_commits` reports
/// the guest's commit and the delta holds the tree without `.git`.
///
/// # Would red if
///
/// The `ro` option were dropped from the history bind, the alternates line
/// were absolute (the guest resolves it to a missing path), the index member
/// lacked its trailer (`git status` reports the index corrupt before any
/// checkout rewrites it), the push destination leaked, or the delta walk let
/// `.git` through.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its installed AppArmor \
             profile, a delegated user scope, and git-minimal's closure realised). \
             Rides the containment lane's oci-live-smoke step. By hand: \
             `cargo nextest run -p kata-worker -P live-smoke \
             -E 'binary(git_view_live)' --run-ignored all`."]
fn live_the_capsules_work_git_view_is_a_disposable_repository() {
    delegated(
        "live_the_capsules_work_git_view_is_a_disposable_repository",
        live_body,
    );
}
