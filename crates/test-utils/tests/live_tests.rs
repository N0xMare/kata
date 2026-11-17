//! Tests for `crates/test-utils/src/live.rs`. Extracted from the
//! inline `#[cfg(test)]` module.
//!
//! These exercise the private binary resolver,
//! capability-spec renderer, and TOML config renderer in isolation —
//! NOT the live-binary spawn paths (those live in `live_smoke.rs`
//! and require a built `target/release/kata`).
//!
//! Private items reach this file via the `live::testing` re-export
//! module, per the `kata-test-utils` test convention.

use std::path::{Path, PathBuf};

use kata_test_utils::live::testing::{
    NodeConfigOptions, bin_path, capability_to_spec, render_node_config, workspace_target_release,
};
use kata_test_utils::live::{CapacityTopology, LiveError, TelemetrySpec, VcsSpec};

/// `workspace_target_release` resolves to a `target/release`
/// path under the workspace root. Unit-test pin: keeps the
/// `CARGO_MANIFEST_DIR`-walking logic from drifting silently
/// if someone moves the test-utils crate.
#[test]
fn workspace_target_release_ends_with_target_release() {
    let path = workspace_target_release();
    let s = path.to_string_lossy();
    assert!(
        s.ends_with("target/release"),
        "workspace target release should end in target/release, got {s}"
    );
}

/// `bin_path` returns `BinaryMissing` when the binary is not
/// at the resolved location. We don't mutate
/// `KATA_LIVE_BIN_DIR` (env mutation in tests is unsafe in
/// edition 2024), so this test exercises only the
/// workspace-target fallback. In a checked-out worktree
/// where `target/release/<name>` does not exist (the default
/// for a fresh `cargo build` of just this crate), the
/// resolver returns `BinaryMissing(<workspace>/target/release/<name>)`.
/// Skipped if a built binary is already present.
#[test]
fn bin_path_missing_returns_typed_error() {
    // Use a name no binary in the workspace produces.
    let err = bin_path("definitely-not-a-real-kata-binary-name").expect_err("must be missing");
    match err {
        LiveError::BinaryMissing(p) => {
            assert!(
                p.ends_with("definitely-not-a-real-kata-binary-name"),
                "missing path should end in the binary name, got {}",
                p.display()
            );
        }
        other => panic!("expected BinaryMissing, got {other:?}"),
    }
}

/// `capability_to_spec` round-trips through
/// `WorkerResource::from_str` for every variant.
#[test]
fn capability_to_spec_roundtrips() {
    use kata_types::agent::BackendType;
    use kata_types::identity::WorkerResource;
    use std::str::FromStr as _;

    let cases = vec![
        WorkerResource::Shell,
        WorkerResource::Network,
        WorkerResource::AgentBackend(BackendType::Harness),
        WorkerResource::Disk { min_gb: 50 },
        WorkerResource::Gpu { min_vram_gb: 24 },
        WorkerResource::Custom("offline-zone-a".into()),
    ];
    for cap in cases {
        let spec = capability_to_spec(&cap);
        let back = WorkerResource::from_str(&spec)
            .unwrap_or_else(|e| panic!("roundtrip failed for {spec}: {e}"));
        assert_eq!(back, cap, "spec {spec} did not round-trip");
    }
}

/// `render_node_config` produces a TOML string that contains
/// the bind address, data dir, and the supervised-node transport and no
/// node-role surface — and every rendered node is an
/// `oci` node carrying the mandatory `[node] environment` declaration.
#[test]
fn render_node_config_supervised_node_capacity() {
    let s = render_node_config(
        CapacityTopology::SupervisedNode,
        Path::new("/tmp/kata-live-test"),
        "127.0.0.1:18400".parse().unwrap(),
        None,
        &NodeConfigOptions::default(),
    );
    assert!(!s.contains("role ="), "nodes carry no role key: {s}");
    assert!(!s.contains("name ="), "nodes carry no name key: {s}");
    assert!(
        s.contains("id = \"kata-live-supervised\""),
        "missing installed-main identity in {s}"
    );
    assert!(
        s.contains("bind = \"127.0.0.1:18400\""),
        "missing bind in {s}"
    );
    assert!(
        s.contains("type = \"supervised_node\""),
        "a supervising main must declare the supervised_node transport"
    );
    assert!(
        s.contains("[agents.shell]\n") && !s.contains("[agents.default]"),
        "a supervising main's one agent is the deterministic shell route: {s}"
    );
    assert!(
        !s.contains("execution_profile"),
        "there is no such key — the harness renders no profile line: {s}"
    );
    assert!(
        s.contains("environment = {"),
        "an `oci` node must declare its environment (node_environment_undeclared): {s}"
    );
    // No [telemetry] block when telemetry arg is None.
    assert!(
        !s.contains("[telemetry]"),
        "default spawn_supervised_main must not inject [telemetry]"
    );
}

/// The same installed main can instead expose local-socket worker capacity.
#[test]
fn render_node_config_local_socket_capacity() {
    let sock = PathBuf::from("/tmp/kata-live/worker.sock");
    let s = render_node_config(
        CapacityTopology::LocalSocket,
        Path::new("/tmp/kata-live-test"),
        "127.0.0.1:18401".parse().unwrap(),
        Some(&sock),
        &NodeConfigOptions::default(),
    );
    assert!(!s.contains("role ="), "nodes carry no role key: {s}");
    assert!(
        s.contains("id = \"kata-live-local-socket\""),
        "missing installed-main identity in {s}"
    );
    assert!(
        s.contains("type = \"local_socket\""),
        "external capacity must use local_socket"
    );
    assert!(
        s.contains("/tmp/kata-live/worker.sock"),
        "local-socket capacity must wire the worker.sock path"
    );
}

/// The rendered TOML includes a `[telemetry]` block
/// with the spec's fields when a spec is passed.
#[test]
fn render_node_config_injects_telemetry_block() {
    let spec = TelemetrySpec {
        export: "prometheus".into(),
        metrics_bind: "127.0.0.1:18500".parse().unwrap(),
        otlp_endpoint: String::new(),
    };
    let s = render_node_config(
        CapacityTopology::SupervisedNode,
        Path::new("/tmp/kata-live-test"),
        "127.0.0.1:18400".parse().unwrap(),
        None,
        &NodeConfigOptions {
            telemetry: Some(spec),
            ..NodeConfigOptions::default()
        },
    );
    assert!(s.contains("[telemetry]"), "missing [telemetry] in {s}");
    assert!(s.contains("export = \"prometheus\""));
    assert!(s.contains("metrics_bind = \"127.0.0.1:18500\""));
}

/// Live smokes that root the jj provider at their own repository get a `[vcs]`
/// block naming it — and never an `execution_workspace_backend` key,
/// which the loader refuses by name.
#[test]
fn render_node_config_injects_vcs_block() {
    let spec = VcsSpec::native_jj(PathBuf::from("/tmp/kata-live-jj-repo"));
    let s = render_node_config(
        CapacityTopology::SupervisedNode,
        Path::new("/tmp/kata-live-test"),
        "127.0.0.1:18400".parse().unwrap(),
        None,
        &NodeConfigOptions {
            vcs: Some(spec),
            ..NodeConfigOptions::default()
        },
    );

    assert!(s.contains("[vcs]"), "missing [vcs] in {s}");
    assert!(
        !s.contains("execution_workspace_backend"),
        "the refused key must not be rendered: {s}"
    );
    assert!(
        s.contains("jj_repo = \"/tmp/kata-live-jj-repo\""),
        "missing jj repo path in {s}"
    );
}

/// **EVERY CONFIG THE LIVE HARNESS RENDERS PARSES THROUGH THE CLOSED DOOR** — both
/// capacity topologies, bare and with every optional block (`[telemetry]`, `[vcs]`,
/// egress). `kata.toml` refuses a key no section declares, and a live rig
/// boots the rendered text through that refusal; this pins it without a boot.
#[test]
fn every_rendered_node_config_parses_through_the_closed_door() {
    let sock = PathBuf::from("/tmp/kata-live/worker.sock");
    let full = NodeConfigOptions {
        telemetry: Some(TelemetrySpec {
            export: "prometheus".into(),
            metrics_bind: "127.0.0.1:18500".parse().unwrap(),
            otlp_endpoint: String::new(),
        }),
        vcs: Some(VcsSpec {
            jj_repo: PathBuf::from("/tmp/kata-live/repo"),
        }),
        egress_allow: vec!["api.example.com:443".into()],
        ..NodeConfigOptions::default()
    };
    for (topology, worker_sock) in [
        (CapacityTopology::SupervisedNode, None),
        (CapacityTopology::LocalSocket, Some(sock.as_path())),
    ] {
        for options in [&NodeConfigOptions::default(), &full] {
            let rendered = render_node_config(
                topology,
                Path::new("/tmp/kata-live-test"),
                "127.0.0.1:18400".parse().unwrap(),
                worker_sock,
                options,
            );
            kata_types::config::parse_kata_config(&rendered, Path::new("rendered.toml"))
                .unwrap_or_else(|error| panic!("{error}\n{rendered}"));
        }
    }
}
