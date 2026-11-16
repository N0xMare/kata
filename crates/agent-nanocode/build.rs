//! Compute `CODE_MODE_ENGINE_DIGEST`: a blake3 over the Code Mode engine as
//! kata runs it — the vendored engine this crate compiles against, kata's patch
//! to it, and kata's interpreter host (`kata-code-mode-host`, which runs every
//! cell in a confined interpreter process behind the engine's seams) — which
//! `harness_identity` folds, so a change to how a cell runs, or to what it
//! reports, moves the executor term even with the nanocode rev and the limit
//! values unchanged.
//!
//! The digest input is every file under [`ROOTS`], sorted by its path relative to
//! the workspace root, each written as `[u64 LE path length][path][u64 LE content
//! length][content]`, the encoding `kata-toolhost-protocol`'s build script uses.
//! The length prefixes make the encoding unambiguous: no two different trees
//! produce the same byte stream.
//!
//! Every root is watched with `rerun-if-changed` (a directory is scanned as a
//! whole), and a root that is missing fails the build.

use std::path::{Path, PathBuf};

/// Relative to the workspace root:
///
/// - the vendored engine, the crate cargo builds (`[patch]` routes every
///   nanocode dependency on it here): every file of it, its manifest,
///   `build.rs`, `README.md`, `src/`, `wasm/` header and licence files;
/// - the patch file `just nanocode-vendor-check` derives that crate from. The
///   tree is what compiles; the patch is folded too, so an edit to it moves the
///   digest even before the tree is re-derived;
/// - kata's interpreter host, the package this crate's `install_code_mode_limits`
///   installs behind the engine's seams: its manifest and its `src/` (not its
///   `tests/`, which no shipped binary compiles). Its syscall filter is a
///   function of more than its source (kata's seccomp compiler, `libc`'s
///   numbers), which `harness_identity` folds as the filter's own digest.
///
/// `tests/nanocode_seam/code_mode_engine_digest.rs`'s
/// `the_engine_digest_is_the_blake3_of_the_engine_as_kata_runs_it` derives the
/// same roots from the workspace manifest (the `[patch]` entry and the host's
/// workspace dependency) and fails when the compiled digest is not theirs.
///
/// Not covered, stated: the registry dependencies of the engine and of the
/// host (djs and the rest, by version or rev in the lockfile), the toolchain, the
/// target and the profile. Which files are tracked: every file on disk under a
/// root is hashed, so a dirty tree states a digest no clean build of the same
/// commit states.
const ROOTS: [&str; 4] = [
    "vendor/nanocode-code-mode-engine",
    "vendor/nanocode-code-mode-engine.patch",
    "crates/code-mode-host/Cargo.toml",
    "crates/code-mode-host/src",
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let manifest_dir = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"),
    );
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("crates/agent-nanocode sits two levels below the workspace root");

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
            .unwrap_or_else(|error| panic!("code mode engine digest: reading {relative}: {error}"));
        hasher.update(&(relative.len() as u64).to_le_bytes());
        hasher.update(relative.as_bytes());
        hasher.update(&(contents.len() as u64).to_le_bytes());
        hasher.update(&contents);
    }
    println!(
        "cargo:rustc-env=KATA_CODE_MODE_ENGINE_DIGEST={}",
        hasher.finalize().to_hex()
    );
}

/// Every regular file at or under `path`. A symlink, or any other non-regular
/// entry, fails the build: the digest names bytes, not where a link points.
fn collect(path: &Path, relative: String, out: &mut Vec<(String, PathBuf)>) {
    let metadata = std::fs::symlink_metadata(path)
        .unwrap_or_else(|error| panic!("code mode engine digest: {relative}: {error}"));
    if metadata.is_file() {
        out.push((relative, path.to_path_buf()));
        return;
    }
    assert!(
        metadata.is_dir(),
        "code mode engine digest: {relative} is neither a regular file nor a directory"
    );
    let entries = std::fs::read_dir(path)
        .unwrap_or_else(|error| panic!("code mode engine digest: listing {relative}: {error}"));
    for entry in entries {
        let entry = entry
            .unwrap_or_else(|error| panic!("code mode engine digest: listing {relative}: {error}"));
        let name = entry.file_name().into_string().unwrap_or_else(|name| {
            panic!(
                "code mode engine digest: {relative}/{} is not a UTF-8 name",
                name.display()
            )
        });
        collect(&entry.path(), format!("{relative}/{name}"), out);
    }
}
