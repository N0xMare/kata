//! The `oci` node profile's config facts: the `[node] environment` every node
//! must declare, the start-deadline leg it may not disable, and the explicit
//! "no node installed" state.
//!
//! # What these cells assert against
//!
//! TOML text an operator could type, parsed by the production loader and the
//! registry the inert-knob guard cross-checks.

use kata_types::config::{NodeConfig, node_knob_registry};

#[derive(Debug, serde::Deserialize)]
struct NodeOnly {
    node: NodeConfig,
}

fn node(text: &str) -> NodeConfig {
    toml::from_str::<NodeOnly>(text)
        .expect("the `[node]` section parses")
        .node
}

fn node_config_text(key: &str) -> String {
    format!("[node]\nid = \"n\"\ndata_dir = \"/var/lib/kata\"\n{key}")
}

// ---------------------------------------------------------------------------
// `[node] environment` — the environment every node must declare
// ---------------------------------------------------------------------------

const ENVIRONMENT: &str = "environment = { label = \"busybox\", system = \"x86_64-linux\", \
     nixpkgs_attribute = \"nixpkgs#pkgsStatic.busybox\", store_paths = \
     [\"/nix/store/qddzvnv6b0805nkvbqddbswddcfhx814-busybox-static-x86_64-unknown-linux-musl-1.37.0\"], \
     path_prepend = [\"/nix/store/qddzvnv6b0805nkvbqddbswddcfhx814-busybox-static-x86_64-unknown-linux-musl-1.37.0/bin\"], \
     integrity_policy = { verify = \"nar_hash_only\", sigs_needed = 0, required_signers = [], \
     allow_unsigned_content_addressed = false, verify_contents_at_declare = true } }\n";

#[test]
fn the_node_environment_parses_through_the_environment_planes_own_types() {
    let cfg = node(&node_config_text(ENVIRONMENT));
    let environment = cfg
        .required_environment()
        .expect("a node that declares its environment boots");
    assert_eq!(environment.system, "x86_64-linux");
    assert_eq!(environment.store_paths.len(), 1);
    assert_eq!(
        environment.integrity_policy.verify,
        kata_types::nix_environment::NarVerification::NarHashOnly
    );
}

/// The refusal names itself and the recourse an operator can paste: `kata host
/// setup` refuses from an undelegated login shell, so the recourse carries the
/// delegated-scope prefix every other `kata host setup` recourse prints.
#[test]
fn a_node_without_an_environment_is_refused_by_name() {
    let cfg = node(&node_config_text(""));
    let refusal = cfg
        .required_environment()
        .expect_err("a capsule binds a closure by id, and this node names none")
        .to_string();
    assert!(
        refusal.contains(kata_types::config::NODE_ENVIRONMENT_UNDECLARED),
        "refused by name: {refusal}"
    );
    assert!(
        refusal.contains("`systemd-run --user --scope -p Delegate=yes -- kata host setup`"),
        "the recourse runs under a delegated scope: {refusal}"
    );
}

#[test]
fn a_flake_reference_or_any_unknown_environment_key_is_refused_by_serde() {
    let error = toml::from_str::<NodeOnly>(&node_config_text(
        &ENVIRONMENT.replace("label = ", "flake = \"nixpkgs#busybox\", label = "),
    ))
    .expect_err("a flake ref is resolved BEFORE a declaration exists, never at boot");
    assert!(error.to_string().contains("flake"), "{error}");
}

#[test]
fn the_environment_knob_carries_a_consumed_registry_row() {
    let row = node_knob_registry()
        .iter()
        .find(|(name, _)| *name == "environment")
        .expect("the consumed-knob rule requires a row for every serde field");
    let marker = format!("{:?}", row.1);
    assert!(
        marker.contains("Consumed") && marker.contains("bind_node_environment"),
        "{marker}"
    );
}

#[test]
fn this_node_has_the_one_qualified_platform() {
    let platform =
        kata_types::node_profile::node_platform().expect("the reference host is x86_64-linux");
    assert_eq!(platform.target(), "x86_64-linux");
}

/// A zero `[workers] assignment_start_deadline_ms` is REFUSED BY NAME at config
/// load — the one leg that settles a capsule delivered and never started cannot
/// be disabled. Loaded through the production loader from a file an operator
/// could write.
///
/// **Would red if:** `KataConfig::validate` stopped refusing the zeroed leg
/// (the config would load with the leg silently off).
#[test]
fn a_node_refuses_a_disabled_start_deadline_by_name() {
    let load = |deadline: u64| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kata.toml");
        std::fs::write(
            &path,
            format!(
                "[node]\nid = \"n\"\ndata_dir = \"{data}\"\n\n\
                 [workers]\ndispatch_deadline_ms = 30000\nassignment_start_deadline_ms = \
                 {deadline}\nheartbeat_interval_ms = 10000\nheartbeat_grace_ms = 30000\n\
                 max_workers = 4\ntransports = [{{ type = \"supervised_node\" }}]\n\n[api]\nbind = \
                 \"127.0.0.1:0\"\nauth = {{ type = \"disabled\" }}\n\n[agents.shell]\n",
                data = dir.path().join("data").display(),
            ),
        )
        .unwrap();
        kata_types::config::load_config_placeholder(&path).map(drop)
    };
    let refusal = load(0)
        .expect_err("the start deadline disabled is refused")
        .to_string();
    assert!(
        refusal.contains(kata_types::config::CAPSULE_START_DEADLINE_DISABLED),
        "{refusal}"
    );
    load(900_000).expect("a start deadline loads");
}

/// "No node installed" is an explicit state, not an overloaded
/// default: a process that never calls `mark_node_installed` answers
/// `node_is_installed() == false`; a boot's install flips the marker; the
/// test-support clear drops it (the state `kata check` sits in).
///
/// **Watched red:** with the `NODE_INSTALLED` write dropped from the mark,
/// `node_is_installed()` stays false after install and this cell's second
/// assert fails.
#[test]
fn no_node_installed_is_an_explicit_state_not_a_default_value() {
    assert!(
        !kata_types::node_profile::node_is_installed(),
        "a fresh process answers no-node"
    );
    kata_types::node_profile::mark_node_installed();
    assert!(
        kata_types::node_profile::node_is_installed(),
        "the mark IS the node's install"
    );
    kata_types::node_profile::clear_node_installation();
    assert!(
        !kata_types::node_profile::node_is_installed(),
        "the test-support clear restores the no-node state"
    );
}
