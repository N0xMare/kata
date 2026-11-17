//! What `kata-effects-contract` may link, refused rather than asserted in a
//! comment.
//!
//! The contract is the boundary kata's main calls the repository and the forge
//! through; the implementation behind it (`kata-vcs`) reads repositories with
//! jj-lib and gix. A main that names only the contract must not link those, so
//! the contract's own closure is checked here, against its exact refused set.

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

/// The repository readers the contract must not link.
const REFUSED: [&str; 3] = ["jj-lib", "gix", "gix-pack"];

/// Every package `package` links: its normal dependencies, transitively, for
/// every platform the lockfile resolves (no `--filter-platform`, so a
/// target-specific dependency is in the closure too). Read from `cargo metadata
/// --locked --offline`, so the lockfile is the input and nothing is fetched or
/// rewritten.
fn linked_closure(package: &str) -> BTreeSet<String> {
    let output = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--locked", "--offline"])
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
    // Each node's NORMAL dependencies: a `dep_kinds` entry whose `kind` is null.
    let mut linked: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for node in metadata["resolve"]["nodes"].as_array().unwrap() {
        let id = node["id"].as_str().unwrap();
        for dependency in node["deps"].as_array().unwrap() {
            let normal = dependency["dep_kinds"]
                .as_array()
                .unwrap()
                .iter()
                .any(|kind| kind["kind"].is_null());
            if normal {
                linked
                    .entry(id)
                    .or_default()
                    .push(dependency["pkg"].as_str().unwrap());
            }
        }
    }
    let root = names
        .iter()
        .find_map(|(id, name)| (*name == package).then_some(*id))
        .unwrap_or_else(|| panic!("{package} is a workspace package"));
    let mut closure = BTreeSet::new();
    let mut frontier = vec![root];
    while let Some(id) = frontier.pop() {
        if closure.insert(id) {
            frontier.extend(linked.get(id).into_iter().flatten().copied());
        }
    }
    closure.iter().map(|id| names[id].to_owned()).collect()
}

/// The refused set: a package named `jj-lib`, `gix` or `gix-pack` in
/// `kata-effects-contract`'s linked closure ([`linked_closure`]), nothing else:
/// another `gix-*` crate alone is not refused.
///
/// The control walks `kata-vcs`, which links all three, so a misspelled name or
/// a walk that stops early cannot pass vacuously.
///
/// **Would red if:** the contract gained a dependency that links jj-lib, gix or
/// gix-pack — `kata-vcs` itself included (watched red with `jj-lib` added).
#[test]
fn the_contract_links_no_jj_lib_gix_or_gix_pack() {
    let implementation = linked_closure("kata-vcs");
    for refused in REFUSED {
        assert!(
            implementation.contains(refused),
            "the control walk from kata-vcs reached no {refused}"
        );
    }

    let contract = linked_closure("kata-effects-contract");
    assert!(
        contract.contains("kata-types"),
        "the walk from the contract reached no kata-types: {contract:?}"
    );
    let linked: Vec<&str> = REFUSED
        .into_iter()
        .filter(|refused| contract.contains(*refused))
        .collect();
    assert_eq!(
        linked,
        Vec::<&str>::new(),
        "kata-effects-contract links them"
    );
}
