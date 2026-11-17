//! Real filesystem exhaustion during current-format recovery publication.
use super::*;
use std::io::Write as _;
use std::path::PathBuf;

const CHILD_ROOT: &str = "KATA_TEST_RECOVERY_DISK_FULL_ROOT";
const TEST: &str = "cli::recovery_capture::disk_full_tests::recovery_capture_real_enospc_refuses_unpublished_artifacts";

fn source_witness(data: &Path) -> (Vec<u8>, Vec<String>, i64) {
    let local = rusqlite::Connection::open_with_flags(
        data.join("idempotency.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert_eq!(
        local
            .query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    let records = local
        .prepare("SELECT hex(membrane_id) FROM membrane_identity")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(
        records.len(),
        1,
        "the exhaustion proof must retain the source replay identity"
    );
    let operational = rusqlite::Connection::open_with_flags(
        data.join("operational.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert_eq!(
        operational
            .query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    let domains = operational
        .query_row("SELECT count(*) FROM worker_effect_domains", [], |row| {
            row.get(0)
        })
        .unwrap();
    (
        std::fs::read(data.join("main-identity.json")).unwrap(),
        records,
        domains,
    )
}

fn fill_then_reserve(root: &Path, reserve: u64) {
    let mut filler = std::fs::File::create(root.join("capacity-filler")).unwrap();
    let block = [0u8; 4096];
    loop {
        match filler.write_all(&block) {
            Ok(()) => {}
            Err(error) => {
                assert_eq!(
                    error.raw_os_error(),
                    Some(libc::ENOSPC),
                    "bounded tmpfs must actually exhaust: {error}"
                );
                println!("capacity witness: real filesystem ENOSPC ({error})");
                break;
            }
        }
    }
    let length = filler.metadata().unwrap().len();
    filler
        .set_len(
            length
                .checked_sub(reserve)
                .expect("reserve fits bounded filesystem"),
        )
        .unwrap();
}

async fn exercise(root: PathBuf) {
    use kata_types::config::{RecoveryRemoteConfig, WorkerTransportConfig};
    use kata_vcs::VcsBackend as _;
    let data = root.join("source");
    let owner = crate::data_dir_lock::DataDirLock::initialize_installed_for_test(&data).unwrap();
    let local = kata_core::IdempotencyStore::open(data.join("idempotency.db")).unwrap();
    let operational = kata_core::OperationalDb::open(data.join("operational.db")).unwrap();
    operational
        .enroll_worker_domain(&owner.identity().directory_id, local.membrane_id().unwrap())
        .unwrap();
    drop(operational);
    drop(local);
    let repo = root.join("repo");
    std::fs::create_dir(&repo).unwrap();
    kata_test_utils::git::init_git_repo_at(&repo);
    drop(kata_vcs::JjBackend::open(&repo).unwrap());
    let remote = root.join("remote.git");
    let initialized = kata_test_utils::git::hermetic_git()
        .args(["init", "--bare"])
        .arg(&remote)
        .output()
        .unwrap();
    assert!(initialized.status.success());
    let snapshot = kata_vcs::jj::recovery_references::with_recovery_references(
        &repo,
        &[],
        &[],
        &[],
        Instant::now() + Duration::from_secs(10),
        |snapshot, _| snapshot.clone(),
    )
    .unwrap();
    for (index, commit) in snapshot.required_commits.iter().enumerate() {
        kata_test_utils::git::run_git(
            &repo,
            &[
                "push",
                remote.to_str().unwrap(),
                &format!("{commit}:refs/heads/recovery-{index}"),
            ],
        );
    }
    let mut config: kata_types::config::KataConfig = toml::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../config/kata.example.toml"
    )))
    .unwrap();
    config.node.data_dir = data.clone();
    config.vcs.jj_repo = repo;
    config.vcs.recovery_remote = Some(RecoveryRemoteConfig {
        id: "exhaustion-remote".into(),
        url: remote.to_string_lossy().into_owned(),
    });
    config.workers.transports = vec![WorkerTransportConfig::SupervisedNode {}];
    let config_path = root.join("kata.toml");
    std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
    let manager = kata_core::ConfigManager::load(&config_path).unwrap();
    let before = source_witness(&data);
    let positive = capture_locked(
        &manager,
        &data,
        &owner.identity().directory_id,
        &root.join("roomy-control"),
    )
    .await
    .unwrap();
    assert_eq!(
        positive.manifest().version,
        kata_core::store::backup::RECOVERY_MANIFEST_VERSION
    );
    assert_eq!(before, source_witness(&data));
    // Whole pages, as the bounded tmpfs accounts them: what the positive capture wrote
    // for its stores and config, and for its recovery members.
    let paged = |recovery_member: bool| -> u64 {
        positive
            .manifest()
            .assets
            .iter()
            .filter(|asset| asset.name.starts_with("recovery/") == recovery_member)
            .map(|asset| asset.byte_len.div_ceil(4096) * 4096)
            .sum()
    };
    let database_bytes = paged(false);
    let member_bytes = paged(true);
    // The member leg leaves room for every store and the config, and for all but the
    // last page of the recovery members, so the exhaustion lands in the member copy
    // whatever the members weigh. A fixed slack cannot: the members are a few pages
    // (the worker store holds only its membrane identity), less than any slack that
    // also absorbs the stores. Nothing is written between the config and the first
    // member (`finish_capture` copies the members before the manifest).
    for (label, reserve, expected) in [
        ("sqlite", 64 * 1024, "VACUUM INTO"),
        (
            "member",
            database_bytes + member_bytes - 4096,
            "recovery: write",
        ),
    ] {
        let limited = root.join(label);
        fill_then_reserve(&limited, reserve);
        let artifact = limited.join("artifact");
        let error = capture_locked(&manager, &data, &owner.identity().directory_id, &artifact)
            .await
            .unwrap_err();
        let diagnostic = format!("{error:#}");
        println!("{label} capture exhaustion: {diagnostic}");
        assert!(
            diagnostic.contains(expected),
            "wrong failure window: {diagnostic}"
        );
        assert!(
            diagnostic.contains("No space left on device")
                || diagnostic.contains("database or disk is full"),
            "not an exhaustion failure: {diagnostic}"
        );
        assert!(!artifact.join("backup-manifest.json").exists());
        assert_eq!(
            before,
            source_witness(&data),
            "capture failure changed source authority"
        );
        std::fs::remove_file(limited.join("capacity-filler")).unwrap();
        let recovered = capture_locked(
            &manager,
            &data,
            &owner.identity().directory_id,
            &limited.join("roomy-retry"),
        )
        .await
        .unwrap();
        assert_eq!(
            recovered.manifest().version,
            kata_core::store::backup::RECOVERY_MANIFEST_VERSION
        );
        assert_eq!(before, source_witness(&data));
    }
    // Exercise the extraction path separately: capture failure cannot establish
    // that a verified artifact refuses partial activation on a full target.
    let limited = root.join("restore");
    fill_then_reserve(&limited, 64 * 1024);
    let artifact = root.join("roomy-control");
    let manifest_before = std::fs::read(artifact.join("backup-manifest.json")).unwrap();
    let verifier = super::super::recovery_artifact_verifier::ArtifactVerifier::new(
        "exhaustion-remote".into(),
        remote.to_string_lossy().into_owned(),
        Instant::now() + Duration::from_secs(30),
    );
    let target = limited.join("partial-target");
    let error =
        kata_core::store::backup::restore_recovery_data_dir(&artifact, &target, None, &verifier)
            .unwrap_err();
    let diagnostic = format!("{error:#}");
    println!("restore extraction exhaustion: {diagnostic}");
    assert!(
        diagnostic.contains("No space left on device"),
        "wrong failure window: {diagnostic}"
    );
    assert!(!target.join("main-identity.json").exists());
    assert_eq!(
        manifest_before,
        std::fs::read(artifact.join("backup-manifest.json")).unwrap()
    );
    assert_eq!(before, source_witness(&data));
    std::fs::remove_file(limited.join("capacity-filler")).unwrap();
    // Keep any interrupted extraction offline; retry a fresh target on the same
    // filesystem, without pretending extraction is full CLI clone activation.
    let retry = limited.join("roomy-retry");
    kata_core::store::backup::restore_recovery_data_dir(&artifact, &retry, None, &verifier)
        .unwrap();
    assert!(
        !retry.join("idempotency.db").exists(),
        "clone extraction must not inherit source replay authority"
    );
    let restored = rusqlite::Connection::open_with_flags(
        retry.join("operational.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert_eq!(
        restored
            .query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    assert_eq!(
        restored
            .query_row("SELECT count(*) FROM worker_effect_domains", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        before.2
    );
    let retained = rusqlite::Connection::open_with_flags(
        retry.join(format!(
            "recovery-evidence/{}/source-main/idempotency.db",
            positive.manifest().artifact_id.unwrap()
        )),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let records = retained
        .prepare("SELECT hex(membrane_id) FROM membrane_identity")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(
        records, before.1,
        "source replay bytes survive only as offline clone evidence"
    );
    assert!(!retry.join("main-identity.json").exists());
    assert_eq!(before, source_witness(&data));
}

/// The three bounded filesystems, by the label `exercise` fills each one under.
const BOUNDED: [&str; 3] = ["sqlite", "member", "restore"];

/// Each bounded filesystem's capacity: small enough to exhaust in milliseconds,
/// large enough to hold the positive control's artifact beside the reserve.
const BOUNDED_BYTES: u64 = 16 * 1024 * 1024;

/// Removes the child container's registration on every path, a panic included:
/// a container left registered makes the next run fail on a name collision
/// rather than on the fact it measures.
struct DeleteOnDrop {
    youki: PathBuf,
    state: PathBuf,
    id: String,
}

impl Drop for DeleteOnDrop {
    fn drop(&mut self) {
        let _ = std::process::Command::new(&self.youki)
            .arg("--root")
            .arg(&self.state)
            .args(["delete", "--force", &self.id])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// The OCI bundle that runs this very test as the CHILD: a rootless container of
/// the PINNED youki — the one runtime `_containment-preconditions`' blocking
/// `rootless OCI` row already proves on this host, and the only one kata ships —
/// in its own user, mount and PID namespaces, with a REAL `size=`-bounded tmpfs
/// at each of `data/<label>`.
///
/// The host view is what the child needs and no more: `/usr`, `/etc` and `/nix`
/// read-only (the dynamic loader, `git`, and the store paths a Nix `PATH`
/// resolves through), `/home` and `/tmp` read-write, the directory holding this
/// test executable and the working directory the runner started it in read-only
/// at their own paths when neither bind reaches them (a checkout may sit on any
/// local disk), the scratch `data` root at its own path wherever `TMPDIR` put
/// it, and a private `TMPDIR`. The container's uid 0 is the invoking uid, so
/// every file the child writes is the caller's.
fn bounded_child_config(data: &Path, exe: &Path) -> serde_json::Value {
    let bind = |path: &str, mode: &str| {
        serde_json::json!({
            "destination": path, "type": "none", "source": path,
            "options": ["rbind", mode, "private"],
        })
    };
    let mut mounts = vec![
        serde_json::json!({ "destination": "/proc", "type": "proc", "source": "proc" }),
        serde_json::json!({
            "destination": "/dev", "type": "tmpfs", "source": "tmpfs",
            "options": ["nosuid", "strictatime", "mode=755", "size=65536k"],
        }),
        bind("/usr", "ro"),
        bind("/etc", "ro"),
    ];
    if Path::new("/nix").is_dir() {
        mounts.push(bind("/nix", "ro"));
    }
    mounts.push(bind("/home", "rw"));
    mounts.push(bind("/tmp", "rw"));
    // Before the data bind, so a checkout path that holds `data` cannot cover it.
    let cwd = std::env::current_dir().unwrap();
    let mut checkout: Vec<&Path> = vec![exe.parent().unwrap(), cwd.as_path()];
    checkout.retain(|path| {
        !["/usr", "/etc", "/nix", "/home", "/tmp"]
            .iter()
            .any(|root| path.starts_with(root))
    });
    checkout.sort();
    checkout.dedup();
    for path in checkout {
        mounts.push(bind(&path.display().to_string(), "ro"));
    }
    mounts.push(bind(&data.display().to_string(), "rw"));
    mounts.push(serde_json::json!({
        "destination": "/kata-test-tmp", "type": "tmpfs", "source": "tmpfs",
        "options": ["mode=0700"],
    }));
    for label in BOUNDED {
        mounts.push(serde_json::json!({
            "destination": data.join(label).display().to_string(),
            "type": "tmpfs", "source": "tmpfs",
            "options": [format!("size={BOUNDED_BYTES}")],
        }));
    }
    let mut env: Vec<String> = std::env::vars()
        .filter(|(key, _)| key != CHILD_ROOT && key != "TMPDIR")
        .map(|(key, value)| format!("{key}={value}"))
        .collect();
    env.push(format!("{CHILD_ROOT}={}", data.display()));
    env.push("TMPDIR=/kata-test-tmp".to_string());
    serde_json::json!({
        "ociVersion": "1.0.2",
        "root": { "path": "rootfs", "readonly": true },
        "process": {
            "args": [exe.display().to_string(), "--exact", TEST, "--ignored", "--nocapture"],
            "cwd": cwd.display().to_string(),
            "terminal": false,
            "user": { "uid": 0, "gid": 0 },
            "env": env,
            "noNewPrivileges": true,
            "capabilities": { "bounding": [], "effective": [], "permitted": [] },
        },
        "mounts": mounts,
        "linux": {
            "namespaces": [
                { "type": "pid" }, { "type": "ipc" }, { "type": "uts" },
                { "type": "mount" }, { "type": "user" }, { "type": "cgroup" },
            ],
            "uidMappings": [
                { "containerID": 0, "hostID": nix::unistd::getuid().as_raw(), "size": 1 },
            ],
            "gidMappings": [
                { "containerID": 0, "hostID": nix::unistd::getgid().as_raw(), "size": 1 },
            ],
        },
    })
}

/// Lay out the bundle's read-only rootfs: a mountpoint for every mount the
/// config names and the merged-`/usr` symlinks the loader and `sh` resolve
/// through.
///
/// The rootfs IS the child's `/`, so it is made `0755` whatever the umask left:
/// recovery's SQLite inspection refuses a temporary root with a group- or
/// world-writable ancestor (`/ (uid 0, mode 0775)`, measured on the first run),
/// exactly as it would on a host.
fn bounded_child_rootfs(rootfs: &Path, config: &serde_json::Value) {
    use std::os::unix::fs::PermissionsExt as _;
    for mount in config["mounts"].as_array().unwrap() {
        let destination = mount["destination"].as_str().unwrap();
        std::fs::create_dir_all(rootfs.join(destination.trim_start_matches('/'))).unwrap();
    }
    for (link, target) in [
        ("bin", "usr/bin"),
        ("sbin", "usr/sbin"),
        ("lib", "usr/lib"),
        ("lib64", "usr/lib64"),
    ] {
        std::os::unix::fs::symlink(target, rootfs.join(link)).unwrap();
    }
    std::fs::set_permissions(rootfs, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
#[ignore = "requires the pinned youki (rootless OCI) and bounded tmpfs; required containment lane"]
fn recovery_capture_real_enospc_refuses_unpublished_artifacts() {
    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(exercise(root.into()));
        return;
    }
    let scratch = tempfile::tempdir().unwrap();
    let data = scratch.path().join("data");
    for label in BOUNDED {
        std::fs::create_dir_all(data.join(label)).unwrap();
    }
    let bundle = scratch.path().join("bundle");
    let config = bounded_child_config(&data, &std::env::current_exe().unwrap());
    bounded_child_rootfs(&bundle.join("rootfs"), &config);
    std::fs::write(
        bundle.join("config.json"),
        serde_json::to_vec_pretty(&config).unwrap(),
    )
    .unwrap();

    let youki = PathBuf::from(kata_types::youki_pin::YoukiPin::embedded().store_path());
    let state = scratch.path().join("state");
    let id = format!("kata-recovery-disk-full-{}", std::process::id());
    let _registered = DeleteOnDrop {
        youki: youki.clone(),
        state: state.clone(),
        id: id.clone(),
    };
    // FILES, never pipes: a piped stderr is inherited by the container's init,
    // and reading it to EOF waits on a process the runtime does not own.
    let stdout_path = scratch.path().join("child.out");
    let stderr_path = scratch.path().join("child.err");
    let mut child = std::process::Command::new(&youki)
        .arg("--root")
        .arg(&state)
        .args(["run", "--bundle"])
        .arg(&bundle)
        .arg(&id)
        .stdin(std::process::Stdio::null())
        .stdout(std::fs::File::create(&stdout_path).unwrap())
        .stderr(std::fs::File::create(&stderr_path).unwrap())
        .spawn()
        .expect("the containment lane requires the pinned youki at its pinned path");
    // The bound sits UNDER the live-smoke profile's 300 s terminate, so the
    // timeout path is this test's own panic — which unwinds through
    // `DeleteOnDrop` and force-deletes the container. A nextest SIGKILL would not
    // unwind: the rootless container (its own PID namespace, not a child the
    // kernel reaps with this process) would then be left for
    // `youki --root <state> delete --force <id>`.
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > Duration::from_secs(240) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the bounded-filesystem child did not finish within 240 s");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let stdout = std::fs::read_to_string(&stdout_path).unwrap_or_default();
    let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
    assert!(
        status.success(),
        "bounded filesystem child failed: {status}\n{stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("1 passed"),
        "child selected no test: {stdout}"
    );
    println!("{stdout}");
}
