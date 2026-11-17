//! The NODE's boot declaration of its Nix environment
//! (`kata_core::environment::bind_node_environment`), against a REAL nix on a
//! disposable local store.
//!
//! # What each cell reads
//!
//! A SECOND raw rusqlite handle on `operational.db`, the gc-root directory tree on
//! disk, and `nix-store --query --roots` spawned by this file — never the plane's own
//! typed readers. A host without `nix` FAILS by name (`require_available`); there is
//! no skip.
//!
//! # The store is disposable
//!
//! `NixStore::Local(<tempdir>/store)`, which this process owns: `nix store add-path`
//! into it works unprivileged, which is the pattern `nix_environment_plane.rs` uses. Production
//! passes `NixStore::Daemon`; the binding function takes
//! the store as an argument precisely so this cell can exist.

use std::path::{Path, PathBuf};
use std::process::Command;

use kata_core::OperationalDb;
use kata_core::environment::nix as nix_cli;
use kata_core::environment::{
    NODE_ENVIRONMENT_PLATFORM_MISMATCH, NODE_ENVIRONMENT_SUPERSEDED, NixStore,
    bind_node_environment, roots,
};
use kata_core::store::cas::CasStore;
use kata_types::config::NodeEnvironmentConfig;
use kata_types::nix_environment::{IntegrityPolicy, NarVerification, StorePath};

struct Planes {
    dir: tempfile::TempDir,
    data_dir: PathBuf,
    op_path: PathBuf,
    db: OperationalDb,
    cas: CasStore,
    store: NixStore,
}

fn planes() -> Planes {
    nix_cli::require_available()
        .expect("this plane requires the nix CLI; a host that cannot run it produces a RED");
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let op_path = data_dir.join("operational.db");
    let db = OperationalDb::open(&op_path).unwrap();
    let cas = CasStore::open(data_dir.join("cas.db"), data_dir.join("cas")).unwrap();
    let store = NixStore::Local(dir.path().join("store"));
    Planes {
        dir,
        data_dir,
        op_path,
        db,
        cas,
        store,
    }
}

/// Import a one-file tree into the disposable store and return its store path.
fn store_path(planes: &Planes, name: &str, payload: &str) -> StorePath {
    let source = planes.dir.path().join(name);
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("payload"), payload).unwrap();
    nix_cli::add_path(&planes.store, &source).expect("add-path into the disposable store")
}

fn declaration(label: &str, system: &str, path: StorePath) -> NodeEnvironmentConfig {
    NodeEnvironmentConfig {
        label: label.to_owned(),
        system: system.to_owned(),
        nixpkgs_attribute: "fixture#tree".into(),
        store_paths: vec![path],
        path_prepend: Vec::new(),
        // `add-path` objects are content-addressed and unsigned; nix accepts those
        // unconditionally, and this policy says kata does too.
        integrity_policy: IntegrityPolicy {
            verify: NarVerification::NarHashOnly,
            sigs_needed: 0,
            required_signers: Vec::new(),
            allow_unsigned_content_addressed: true,
            verify_contents_at_declare: true,
        },
    }
}

fn raw(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
}

/// `(environment_id, promoted, released)` for every row, through a second handle.
fn raw_rows(op_path: &Path) -> Vec<(Vec<u8>, bool, bool)> {
    let conn = raw(op_path);
    let mut statement = conn
        .prepare(
            "SELECT environment_id, root_promoted_at_ms IS NOT NULL, released_at_ms IS NOT NULL \
               FROM nix_environments ORDER BY environment_id",
        )
        .unwrap();
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

/// Every entry under a directory, or none when it does not exist — read off the disk.
fn entries(directory: &Path) -> Vec<String> {
    let Ok(read) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut names: Vec<String> = read
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// `nix-store --query --roots` — what NIX believes roots this path.
fn nix_roots(planes: &Planes, path: &StorePath) -> String {
    let NixStore::Local(store) = &planes.store else {
        unreachable!("every cell drives a disposable local store")
    };
    let output = Command::new("nix-store")
        .args(["--store", &store.display().to_string()])
        .args(["--query", "--roots", path.as_str()])
        .output()
        .expect("nix-store --query --roots");
    assert!(output.status.success());
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn node_platform() -> kata_types::execution_contract::PlatformRef {
    kata_types::node_profile::node_platform()
        .expect("the reference host is x86_64-linux, the one qualified target")
}

#[test]
fn the_node_environment_is_declared_promoted_and_rooted_before_it_is_bound() {
    let planes = planes();
    let path = store_path(&planes, "busybox-standin", "closure payload\n");
    let bound = bind_node_environment(
        &planes.db,
        &planes.cas,
        &planes.store,
        &planes.data_dir,
        &declaration("node-env", "x86_64-linux", path.clone()),
        Some(&node_platform()),
    )
    .expect("a node declaring a valid closure for its own platform binds it");

    let rows = raw_rows(&planes.op_path);
    assert_eq!(
        rows,
        vec![(bound.environment.0.0.to_vec(), true, false)],
        "exactly ONE active row, PROMOTED, whose id is the bound one"
    );
    assert_eq!(bound.platform, node_platform().id());
    // The gc root is on disk at its stable path and nix itself sees it.
    let env_dir = roots::environment_directory(&planes.data_dir, bound.environment.0.0);
    assert_eq!(
        entries(&env_dir).len(),
        1,
        "one promoted gc-root link: {env_dir:?}"
    );
    assert!(
        entries(&roots::staging_root(&planes.data_dir)).is_empty(),
        "no staging generation survives a completed declaration"
    );
    let reported = nix_roots(&planes, &path);
    assert!(
        reported.contains(&env_dir.display().to_string()),
        "nix must report the promoted link as a root of the closure: {reported}"
    );
}

#[test]
fn rebooting_with_the_same_declaration_binds_the_same_id_and_writes_nothing_new() {
    let planes = planes();
    let path = store_path(&planes, "tree", "stable\n");
    let first = bind_node_environment(
        &planes.db,
        &planes.cas,
        &planes.store,
        &planes.data_dir,
        &declaration("node-env", "x86_64-linux", path.clone()),
        Some(&node_platform()),
    )
    .expect("first boot binds");
    let rows_before = raw_rows(&planes.op_path);
    let links_before = entries(&roots::environment_directory(
        &planes.data_dir,
        first.environment.0.0,
    ));

    // A second BOOT: new handles on the same directory, same declaration.
    let db = OperationalDb::open(&planes.op_path).unwrap();
    let cas = CasStore::open(planes.data_dir.join("cas.db"), planes.data_dir.join("cas")).unwrap();
    let second = bind_node_environment(
        &db,
        &cas,
        &planes.store,
        &planes.data_dir,
        &declaration("node-env", "x86_64-linux", path),
        Some(&node_platform()),
    )
    .expect("an unchanged declaration re-binds");

    assert_eq!(second, first, "same declaration, same environment id");
    assert_eq!(
        raw_rows(&planes.op_path),
        rows_before,
        "no second row, and the stored one unchanged"
    );
    assert_eq!(
        entries(&roots::environment_directory(
            &planes.data_dir,
            first.environment.0.0
        )),
        links_before,
        "no second gc root"
    );
    assert!(entries(&roots::staging_root(&planes.data_dir)).is_empty());
}

#[test]
fn a_declaration_for_another_platform_is_refused_before_anything_is_realised() {
    let planes = planes();
    let path = store_path(&planes, "tree", "wrong platform\n");
    for (system, platform) in [
        ("aarch64-linux", Some(node_platform())),
        // A binary built for a target with no qualified platform.
        ("x86_64-linux", None),
    ] {
        let refusal = bind_node_environment(
            &planes.db,
            &planes.cas,
            &planes.store,
            &planes.data_dir,
            &declaration("node-env", system, path.clone()),
            platform.as_ref(),
        )
        .expect_err("a closure for another platform is not this node's")
        .to_string();
        assert!(
            refusal.contains(NODE_ENVIRONMENT_PLATFORM_MISMATCH),
            "refused by name: {refusal}"
        );
    }
    assert!(raw_rows(&planes.op_path).is_empty(), "no row was written");
    assert!(
        entries(&roots::staging_root(&planes.data_dir)).is_empty()
            && entries(&roots::environment_root(&planes.data_dir)).is_empty(),
        "and no gc root was staged"
    );
}

#[test]
fn a_different_live_environment_from_a_previous_boot_refuses_boot_rather_than_being_chosen() {
    let planes = planes();
    let old = store_path(&planes, "old", "previous boot\n");
    let old_path = old.clone();
    let new = store_path(&planes, "new", "this boot\n");
    let previous = bind_node_environment(
        &planes.db,
        &planes.cas,
        &planes.store,
        &planes.data_dir,
        &declaration("node-env", "x86_64-linux", old.clone()),
        Some(&node_platform()),
    )
    .expect("the previous boot bound its environment");
    let rows_before = raw_rows(&planes.op_path);
    let env_dirs_before = entries(&roots::environment_root(&planes.data_dir));

    let refusal = bind_node_environment(
        &planes.db,
        &planes.cas,
        &planes.store,
        &planes.data_dir,
        &declaration("node-env", "x86_64-linux", new.clone()),
        Some(&node_platform()),
    )
    .expect_err("a second live environment must refuse boot, not be picked or released")
    .to_string();
    assert!(
        refusal.contains(NODE_ENVIRONMENT_SUPERSEDED),
        "refused by name: {refusal}"
    );
    // The recourse is EXECUTABLE: the previous declaration is printed as TOML an operator
    // can paste back, read from its manifest in CAS, and it parses as the knob it names.
    let toml_start = refusal
        .find("[node.environment]")
        .expect("the previous declaration is printed as TOML");
    assert!(refusal.contains(old_path.as_str()), "{refusal}");
    let pasted: toml::Value = toml::from_str(
        refusal[toml_start..]
            .split("\nfrom a previous boot")
            .next()
            .unwrap()
            .split(" from a previous boot")
            .next()
            .unwrap(),
    )
    .unwrap_or_else(|error| panic!("the printed declaration parses as TOML ({error}): {refusal}"));
    assert_eq!(
        pasted["node"]["environment"]["store_paths"][0].as_str(),
        Some(old_path.as_str())
    );
    assert!(
        refusal.contains("kata node environment release"),
        "{refusal}"
    );
    assert_eq!(
        raw_rows(&planes.op_path),
        rows_before,
        "the previous environment is NOT released and no row was written for the new one"
    );
    assert_eq!(
        entries(&roots::environment_root(&planes.data_dir)),
        env_dirs_before,
        "no gc root for the new closure"
    );
    assert!(entries(&roots::staging_root(&planes.data_dir)).is_empty());
    assert!(
        nix_roots(&planes, &old).contains(
            &roots::environment_directory(&planes.data_dir, previous.environment.0.0)
                .display()
                .to_string()
        ),
        "the previous closure is still rooted"
    );
    assert!(
        !nix_roots(&planes, &new).contains(&planes.data_dir.display().to_string()),
        "and the new one is rooted by nothing under this data directory"
    );
}

/// A `nix store sign` (or a re-substitution) changes a store object's SIGNATURES and
/// nothing else, and an UNCHANGED declaration must still bind the SAME environment and
/// boot — before, signatures were folded into the id and this refused
/// `node_environment_superseded` with no recourse. The new signature is recorded as
/// evidence, read through a second handle.
#[test]
fn re_signing_the_closure_leaves_the_environment_id_and_the_boot_unchanged() {
    let planes = planes();
    let path = store_path(&planes, "tree", "signed later\n");
    let first = bind_node_environment(
        &planes.db,
        &planes.cas,
        &planes.store,
        &planes.data_dir,
        &declaration("node-env", "x86_64-linux", path.clone()),
        Some(&node_platform()),
    )
    .expect("first boot binds");

    let key = planes.dir.path().join("signing.key");
    let generated = Command::new("nix")
        .args(["key", "generate-secret", "--key-name", "kata-test-1"])
        .output()
        .expect("nix key generate-secret");
    assert!(generated.status.success());
    std::fs::write(&key, &generated.stdout).unwrap();
    let NixStore::Local(store) = &planes.store else {
        unreachable!()
    };
    let signed = Command::new("nix")
        .args(["--store", &store.display().to_string()])
        .args(["store", "sign", "--key-file"])
        .arg(&key)
        .arg(path.as_str())
        .output()
        .expect("nix store sign");
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );

    let second = bind_node_environment(
        &planes.db,
        &planes.cas,
        &planes.store,
        &planes.data_dir,
        &declaration("node-env", "x86_64-linux", path),
        Some(&node_platform()),
    )
    .expect("a re-signed but unchanged closure still boots");
    assert_eq!(second, first, "the environment id does not fold signatures");
    assert_eq!(raw_rows(&planes.op_path).len(), 1, "no second row");
    let evidence: Vec<u8> = raw(&planes.op_path)
        .query_row(
            "SELECT verification_evidence FROM nix_environments",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        String::from_utf8_lossy(&evidence).contains("kata-test-1:"),
        "the new signature is recorded as evidence"
    );
}

/// A declared row whose gc root is GONE is RE-ROOTED on the next boot when the store still
/// holds the closure — the id is a function of the bytes just verified — rather than
/// refused with a recourse nobody could run.
#[test]
fn a_rootless_row_is_re_rooted_when_the_store_still_holds_the_closure() {
    let planes = planes();
    let path = store_path(&planes, "tree", "rooted again\n");
    let bound = bind_node_environment(
        &planes.db,
        &planes.cas,
        &planes.store,
        &planes.data_dir,
        &declaration("node-env", "x86_64-linux", path.clone()),
        Some(&node_platform()),
    )
    .unwrap();
    roots::remove_links(&planes.data_dir, bound.environment.0.0).unwrap();
    let env_dir = roots::environment_directory(&planes.data_dir, bound.environment.0.0);
    assert!(entries(&env_dir).is_empty(), "the premise: rootless");
    let again = bind_node_environment(
        &planes.db,
        &planes.cas,
        &planes.store,
        &planes.data_dir,
        &declaration("node-env", "x86_64-linux", path.clone()),
        Some(&node_platform()),
    )
    .expect("the same bytes re-root");
    assert_eq!(again, bound);
    assert!(
        nix_roots(&planes, &path).contains(&env_dir.display().to_string()),
        "nix reports the re-established root"
    );
}

/// A DEAD daemon (nothing listening at the daemon socket) and a HUNG one (a socket that
/// accepts and never answers) each refuse the boot BY NAME, the hung one within the exec
/// deadline rather than never. `NIX_REMOTE` points the real `nix` at a socket this cell
/// owns; nothing touches the host's daemon.
#[test]
fn a_dead_or_hung_nix_daemon_refuses_boot_by_name_within_the_deadline() {
    let planes = planes();
    let path = store_path(&planes, "tree", "daemon\n");
    // SAFETY-free: this test process is its own (nextest runs one test per process).
    let dead = planes.dir.path().join("dead.sock");
    let hung = planes.dir.path().join("hung.sock");
    let _listener = kata_transport::unix_socket::bind_std(&hung).unwrap();
    kata_core::environment::nix::set_exec_deadline_for_test(std::time::Duration::from_secs(3));
    for socket in [&dead, &hung] {
        let started = std::time::Instant::now();
        let refusal = std::process::Command::new(std::env::current_exe().unwrap())
            .env("KATA_NIX_DAEMON_CELL_SOCKET", socket)
            .env("NIX_REMOTE", format!("unix://{}", socket.display()))
            .args([
                "--exact",
                "daemon_cell_child",
                "--nocapture",
                "--include-ignored",
            ])
            .env("KATA_NIX_DAEMON_CELL_PATH", path.as_str())
            .output()
            .expect("the child runs");
        let stdout = String::from_utf8_lossy(&refusal.stdout).into_owned();
        assert!(
            stdout.contains(kata_core::environment::NODE_ENVIRONMENT_NIX_UNAVAILABLE),
            "{}: refused by name: {stdout}{}",
            socket.display(),
            String::from_utf8_lossy(&refusal.stderr)
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(60),
            "bounded, not forever"
        );
    }
}

/// A `nix` whose `nix-command` feature is off refuses `nix store info` itself, and boot
/// refuses by name with a remedy that names the feature and where it is enabled — not
/// only "start the daemon", which would point an operator at the wrong cause.
/// `NIX_CONFIG` turns the feature off for the child alone, and `NIX_REMOTE` points it at
/// a socket this cell owns, so neither the host's nix.conf nor its daemon is touched. The
/// cause is read out of nix's own text, not kata's.
#[test]
fn a_nix_without_the_nix_command_feature_refuses_boot_naming_the_feature() {
    let planes = planes();
    let path = store_path(&planes, "tree", "feature\n");
    let dead = planes.dir.path().join("dead.sock");
    let refusal = std::process::Command::new(std::env::current_exe().unwrap())
        .env("KATA_NIX_DAEMON_CELL_SOCKET", &dead)
        .env("NIX_REMOTE", format!("unix://{}", dead.display()))
        .env("NIX_CONFIG", "experimental-features = ")
        .args([
            "--exact",
            "daemon_cell_child",
            "--nocapture",
            "--include-ignored",
        ])
        .env("KATA_NIX_DAEMON_CELL_PATH", path.as_str())
        .output()
        .expect("the child runs");
    let stdout = String::from_utf8_lossy(&refusal.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&refusal.stderr).into_owned();
    assert!(
        stdout.contains(kata_core::environment::NODE_ENVIRONMENT_NIX_UNAVAILABLE),
        "refused by name: {stdout}{stderr}"
    );
    assert!(
        stdout.contains("'nix-command' is disabled"),
        "nix itself named the feature as the cause: {stdout}{stderr}"
    );
    assert!(
        stdout.contains("experimental-features = nix-command"),
        "the remedy names the feature and the setting that enables it: {stdout}{stderr}"
    );
}

/// The child half of the daemon cell: binds against `NixStore::Daemon` with the env the
/// parent set, and prints the refusal. Ignored unless the parent runs it.
#[test]
#[ignore = "driven by a_dead_or_hung_nix_daemon_refuses_boot_by_name_within_the_deadline"]
fn daemon_cell_child() {
    if std::env::var_os("KATA_NIX_DAEMON_CELL_SOCKET").is_none() {
        return;
    }
    kata_core::environment::nix::set_exec_deadline_for_test(std::time::Duration::from_secs(3));
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let db = OperationalDb::open(data_dir.join("operational.db")).unwrap();
    let cas = CasStore::open(data_dir.join("cas.db"), data_dir.join("cas")).unwrap();
    let path = StorePath::new(std::env::var("KATA_NIX_DAEMON_CELL_PATH").unwrap()).unwrap();
    let refusal = bind_node_environment(
        &db,
        &cas,
        &NixStore::Daemon,
        &data_dir,
        &declaration("node-env", "x86_64-linux", path),
        Some(&node_platform()),
    )
    .expect_err("an unreachable daemon refuses")
    .to_string();
    println!("{refusal}");
}
