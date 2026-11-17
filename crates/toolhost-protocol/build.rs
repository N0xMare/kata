//! Compute `TOOLHOST_SOURCE_DIGEST`: a blake3 over the in-tree source
//! `kata-toolhost` compiles in, so the
//! worker and `kata-toolhost` compile the same constant and the toolhost's `Hello`
//! can be checked against it.
//!
//! The digest input is every file under [`ROOTS`], sorted by its path relative to
//! the workspace root, each written as `[u64 LE path length][path][u64 LE content
//! length][content]`. The length prefixes make the encoding unambiguous: no two
//! different trees produce the same byte stream.
//!
//! Every root is watched with `rerun-if-changed` (a directory is scanned as a
//! whole), and a root that is missing fails the build. Cargo re-runs a build
//! script on every invocation while a watched path is missing, and a digest that
//! skipped a root would claim coverage it does not have.

use std::path::{Path, PathBuf};

/// The source the digest covers, relative to the workspace root: every
/// in-tree package `kata-toolhost` compiles in (its normal-dependency closure
/// over path dependencies), each as its manifest and its `src/`. That is the
/// toolhost, this wire, and `kata-provider-protocol`, whose frame codec this
/// wire re-exports. `tests::the_roots_are_the_toolhosts_in_tree_closure`
/// derives the same closure from `cargo metadata` and fails when it and this
/// list differ.
///
/// Not covered, stated:
/// * The versions of the toolhost's registry dependencies: a tokio or rustix
///   bump inside the lockfile moves no root, the stance the executor term takes
///   on the provider entry.
/// * The toolchain, the target and the profile: a debug build, a release build
///   and a musl build of one tree state one digest.
/// * The workspace root `Cargo.toml`, although each covered package inherits
///   from it: its `[workspace.package]` edition, its `[workspace.lints]`, the
///   features its `[workspace.dependencies]` select and its `[profile]`
///   sections are compile inputs of all three, and a change to them moves no
///   root.
/// * Which files are tracked: every file on disk under a root is hashed, an
///   untracked file or an editor's swap file included, while a nix build sees
///   only tracked files. A dirty tree therefore states a digest no clean build
///   of the same commit states.
///
/// Covered although it ships no byte: each root's `src/` as a whole, so this
/// crate's `src/tests.rs` is hashed. The toolhost's `tests/` directory is not
/// under a root.
const ROOTS: [&str; 6] = [
    "bin/kata-toolhost/Cargo.toml",
    "bin/kata-toolhost/src",
    "crates/provider-protocol/Cargo.toml",
    "crates/provider-protocol/src",
    "crates/toolhost-protocol/Cargo.toml",
    "crates/toolhost-protocol/src",
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let manifest_dir = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"),
    );
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("crates/toolhost-protocol sits two levels below the workspace root");

    let mut files = Vec::new();
    for root in ROOTS {
        let path = workspace_root.join(root);
        println!("cargo:rerun-if-changed={}", path.display());
        collect(&path, root.to_owned(), &mut files);
    }
    files.sort();

    let mut hasher = blake3::Hasher::new();
    for (relative, path) in &files {
        let contents = std::fs::read(path)
            .unwrap_or_else(|error| panic!("toolhost source digest: reading {relative}: {error}"));
        hasher.update(&(relative.len() as u64).to_le_bytes());
        hasher.update(relative.as_bytes());
        hasher.update(&(contents.len() as u64).to_le_bytes());
        hasher.update(&contents);
    }
    println!(
        "cargo:rustc-env=KATA_TOOLHOST_SOURCE_DIGEST={}",
        hasher.finalize().to_hex()
    );
    // The roots themselves, for the test that compares them against the
    // closure `cargo metadata` resolves.
    println!(
        "cargo:rustc-env=KATA_TOOLHOST_SOURCE_ROOTS={}",
        ROOTS.join(",")
    );
}

/// Every regular file at or under `path`. A symlink, or any other non-regular
/// entry, fails the build: the digest names bytes, not where a link points.
fn collect(path: &Path, relative: String, out: &mut Vec<(String, PathBuf)>) {
    let metadata = std::fs::symlink_metadata(path)
        .unwrap_or_else(|error| panic!("toolhost source digest: {relative}: {error}"));
    if metadata.is_file() {
        out.push((relative, path.to_path_buf()));
        return;
    }
    assert!(
        metadata.is_dir(),
        "toolhost source digest: {relative} is neither a regular file nor a directory"
    );
    let entries = std::fs::read_dir(path)
        .unwrap_or_else(|error| panic!("toolhost source digest: listing {relative}: {error}"));
    for entry in entries {
        let entry = entry
            .unwrap_or_else(|error| panic!("toolhost source digest: listing {relative}: {error}"));
        let name = entry.file_name().into_string().unwrap_or_else(|name| {
            panic!(
                "toolhost source digest: {relative}/{} is not a UTF-8 name",
                name.display()
            )
        });
        collect(&entry.path(), format!("{relative}/{name}"), out);
    }
}
