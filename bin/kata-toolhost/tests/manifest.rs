//! What `kata-toolhost` may link, refused rather than asserted in a comment.
//!
//! The toolhost runs inside the capsule as its init and is built static for
//! `x86_64-unknown-linux-musl`. Two claims of its manifest's comment are checked
//! here, each against its exact refused set:
//!
//! 1. its manifest names nothing of kata's but the wire it speaks
//!    (`the_manifest_names_no_internal_crate_but_the_toolhost_protocol`). This
//!    reads one manifest; the wire's own manifest test
//!    (`kata-toolhost-protocol`'s
//!    `the_manifest_names_no_internal_crate_but_the_provider_protocol`) and the
//!    provider protocol's (`kata-worker`'s `provider_supervisor.rs`) hold the
//!    rest of the closure;
//! 2. nothing it links compiles C, so the musl target links it without a musl C
//!    compiler (`no_crate_the_toolhost_links_compiles_c`). The protocol crate's
//!    BUILD script does use a C-building crate (`blake3` hashes the source at build
//!    time); a build dependency runs on the build host and links nothing into the
//!    toolhost, so it is outside the refused set by construction.

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

/// Crates whose presence in a build means C is compiled (or a C toolchain is
/// probed) for the crate that uses them.
const C_BUILDERS: [&str; 4] = ["bindgen", "cc", "cmake", "pkg-config"];

/// The refused set: a dependency, in any dependency table (target-specific ones
/// included), whose name or `package` rename starts with `kata-` and is not
/// `kata-toolhost-protocol`.
///
/// **Would red if:** the toolhost gained `kata-types` or any other internal crate
/// (watched red with `kata-types` added).
#[test]
fn the_manifest_names_no_internal_crate_but_the_toolhost_protocol() {
    let manifest: toml::Table =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
            .unwrap()
            .parse()
            .unwrap();
    let tables = ["dependencies", "build-dependencies", "dev-dependencies"];
    let mut sections: Vec<&toml::Table> = tables
        .iter()
        .filter_map(|name| manifest.get(*name).and_then(toml::Value::as_table))
        .collect();
    if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
        for target in targets.values().filter_map(toml::Value::as_table) {
            sections.extend(
                tables
                    .iter()
                    .filter_map(|name| target.get(*name).and_then(toml::Value::as_table)),
            );
        }
    }
    let mut internal = BTreeSet::new();
    for (name, spec) in sections.into_iter().flatten() {
        let package = spec
            .get("package")
            .and_then(toml::Value::as_str)
            .unwrap_or(name);
        for named in [name.as_str(), package] {
            if named.starts_with("kata-") && named != "kata-toolhost-protocol" {
                internal.insert(named.to_owned());
            }
        }
    }
    assert_eq!(internal, BTreeSet::new());
}

/// The refused set: a package in the toolhost's LINKED closure for
/// `x86_64-unknown-linux-musl` (its normal dependencies, transitively, as cargo's
/// own resolve for that platform states them) that is one of [`C_BUILDERS`] or has a
/// build dependency on one. Read from `cargo metadata --locked --offline`, so the
/// lockfile is the input and nothing is fetched or rewritten.
///
/// **Would red if:** the toolhost linked a crate that compiles C (watched red with
/// `blake3`, whose build script compiles C, added as a dependency).
#[test]
fn no_crate_the_toolhost_links_compiles_c() {
    let output = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--offline",
            "--filter-platform",
            "x86_64-unknown-linux-musl",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo metadata runs");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata is JSON");
    let names: BTreeMap<&str, &str> = metadata["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|package| {
            (
                package["id"].as_str().unwrap(),
                package["name"].as_str().unwrap(),
            )
        })
        .collect();
    // Each node's dependencies, split by kind: `null` is a normal (linked) one.
    let mut linked: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut built_with: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for node in metadata["resolve"]["nodes"].as_array().unwrap() {
        let id = node["id"].as_str().unwrap();
        for dependency in node["deps"].as_array().unwrap() {
            let target = dependency["pkg"].as_str().unwrap();
            for kind in dependency["dep_kinds"].as_array().unwrap() {
                match kind["kind"].as_str() {
                    None => linked.entry(id).or_default().push(target),
                    Some("build") => built_with.entry(id).or_default().push(target),
                    Some(_) => {}
                }
            }
        }
    }
    let root = names
        .iter()
        .find_map(|(id, name)| (*name == "kata-toolhost").then_some(*id))
        .expect("kata-toolhost is a workspace package");
    let mut closure = BTreeSet::new();
    let mut frontier = vec![root];
    while let Some(id) = frontier.pop() {
        if closure.insert(id) {
            frontier.extend(linked.get(id).into_iter().flatten().copied());
        }
    }
    let closure_names: BTreeSet<&str> = closure.iter().map(|id| names[id]).collect();
    for expected in ["kata-toolhost-protocol", "rustix", "tokio"] {
        assert!(
            closure_names.contains(expected),
            "the walk reached no {expected}: {closure_names:?}"
        );
    }
    let compiles_c: Vec<String> = closure
        .iter()
        .filter_map(|id| {
            let name = names[id];
            if C_BUILDERS.contains(&name) {
                return Some(format!("{name} (linked)"));
            }
            built_with
                .get(id)
                .into_iter()
                .flatten()
                .map(|builder| names[builder])
                .find(|builder| C_BUILDERS.contains(builder))
                .map(|builder| format!("{name} (built with {builder})"))
        })
        .collect();
    assert_eq!(compiles_c, Vec::<String>::new());
}
