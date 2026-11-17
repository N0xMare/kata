//! What `kata-program` may link, refused rather than asserted in a comment.
//!
//! The authoring toolchain depends on `kata-types` alone (ADR 0003, "Authoring"):
//! nothing it links may reach a store, a transport, a VCS backend, a worker or an
//! agent, so a program compiles wherever the CLI runs and the toolchain cannot
//! grow a path into the runtime it is judged by. Read from cargo's own resolve
//! (`cargo metadata --locked --offline`), so the lockfile is the input and nothing
//! is fetched or rewritten.

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

/// The refused set: a WORKSPACE package other than `kata-types` reachable from
/// kata-program over NORMAL dependency edges in the resolve `cargo metadata` states —
/// the WORKSPACE's resolve, with features unified across every member (their
/// dev-dependency feature requests included) and every target's platform-specific
/// dependencies included (no `--filter-platform`). That is a superset of what `cargo
/// build -p kata-program` alone links: an optional dependency of a shared crate that
/// only another member's feature turns on is in it, and is refused too. The
/// workspace's own member list names the set, so a crate added to the workspace later
/// is refused without editing this cell. Build and dev dependencies are outside it:
/// they link nothing into the library.
///
/// **Would red if:** kata-program gained `kata-core`, `kata-vcs`, `kata-transport`
/// or any other workspace crate as a dependency, directly or through a third-party
/// crate (watched red with `kata-core` added).
#[test]
fn the_program_links_no_workspace_crate_but_kata_types() {
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
    let members: BTreeSet<&str> = metadata["workspace_members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap())
        .collect();
    // Each node's NORMAL (linked) dependencies: a `null` kind, whatever its target.
    let mut linked: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for node in metadata["resolve"]["nodes"].as_array().unwrap() {
        let id = node["id"].as_str().unwrap();
        for dependency in node["deps"].as_array().unwrap() {
            let target = dependency["pkg"].as_str().unwrap();
            if dependency["dep_kinds"]
                .as_array()
                .unwrap()
                .iter()
                .any(|kind| kind["kind"].is_null())
            {
                linked.entry(id).or_default().push(target);
            }
        }
    }
    let root = members
        .iter()
        .copied()
        .find(|id| names[id] == "kata-program")
        .expect("kata-program is a workspace member");
    let mut closure = BTreeSet::new();
    let mut frontier = vec![root];
    while let Some(id) = frontier.pop() {
        if closure.insert(id) {
            frontier.extend(linked.get(id).into_iter().flatten().copied());
        }
    }
    let closure_names: BTreeSet<&str> = closure.iter().map(|id| names[id]).collect();
    // The walk is not vacuous: it reached the one workspace crate it may link and
    // the frontend it is built on.
    for expected in ["kata-types", "starlark", "minijinja"] {
        assert!(
            closure_names.contains(expected),
            "the walk reached no {expected}: {closure_names:?}"
        );
    }
    let internal: BTreeSet<&str> = closure
        .iter()
        .filter(|id| members.contains(*id) && **id != root)
        .map(|id| names[id])
        .filter(|name| *name != "kata-types")
        .collect();
    assert_eq!(internal, BTreeSet::new());
}
