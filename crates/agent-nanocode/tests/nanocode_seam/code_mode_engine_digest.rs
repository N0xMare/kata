//! The Code Mode engine digest, recomputed from the workspace manifest and the
//! files on disk, outside `build.rs`. A test of its own, not a unit test of
//! `src/lib.rs`: it reads the host's filesystem, which no module of this
//! crate's `src/` may (kata-agent's `adapter_contract`).

/// **The engine digest is the blake3 of the engine as kata runs it, as it
/// is on disk: the crate the workspace's `[patch]` builds, its patch file,
/// and the interpreter host this crate depends on.** The roots are read out
/// of the workspace manifest, not out of `build.rs`: the path the
/// `[patch."https://github.com/nanocodexyz/nanocode"]` entry routes
/// `nanocode-code-mode-engine` to, that path's `.patch` sibling, which
/// `scripts/nanocode-vendor.py` derives the tree from, and the manifest and
/// `src/` of the path the workspace dependency `kata-code-mode-host` names.
/// Every file under them, in `build.rs`'s encoding, hashes to the compiled
/// constant.
///
/// **Would red if:** `build.rs` dropped a root or hashed another (a byte of
/// the engine cargo builds, of kata's patch or of the interpreter host's
/// source would not move the executor term), or the workspace routed the
/// engine or the host to a crate the digest does not read.
#[test]
fn the_engine_digest_is_the_blake3_of_the_engine_as_kata_runs_it() {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest: toml::Table = std::fs::read_to_string(workspace.join("Cargo.toml"))
        .expect("the workspace manifest reads")
        .parse()
        .expect("the workspace manifest parses");
    let engine = manifest["patch"]["https://github.com/nanocodexyz/nanocode"]
        ["nanocode-code-mode-engine"]["path"]
        .as_str()
        .expect("the workspace patches the engine to a path");
    let own: toml::Table = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
    )
    .expect("this crate's manifest reads")
    .parse()
    .expect("this crate's manifest parses");
    assert!(
        own["dependencies"].get("kata-code-mode-host").is_some(),
        "this crate builds against the interpreter host"
    );
    let host = manifest["workspace"]["dependencies"]["kata-code-mode-host"]["path"]
        .as_str()
        .expect("the workspace names the interpreter host by path");
    let roots = [
        engine.to_owned(),
        format!("{engine}.patch"),
        format!("{host}/Cargo.toml"),
        format!("{host}/src"),
    ];

    fn walk(path: &std::path::Path, relative: &str, out: &mut Vec<(String, Vec<u8>)>) {
        if path.is_file() {
            out.push((relative.to_owned(), std::fs::read(path).unwrap()));
            return;
        }
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().into_string().unwrap();
            walk(&entry.path(), &format!("{relative}/{name}"), out);
        }
    }
    let mut files = Vec::new();
    for root in &roots {
        walk(&workspace.join(root), root, &mut files);
    }
    files.sort();
    for sample in [
        "vendor/nanocode-code-mode-engine.patch",
        "vendor/nanocode-code-mode-engine/Cargo.toml",
        "vendor/nanocode-code-mode-engine/src/backend.rs",
        "crates/code-mode-host/Cargo.toml",
        "crates/code-mode-host/src/syscall_filter.rs",
    ] {
        assert!(
            files.iter().any(|(relative, _)| relative == sample),
            "{sample} is not among the digest's inputs"
        );
    }
    let mut hasher = blake3::Hasher::new();
    for (relative, contents) in &files {
        hasher.update(&(relative.len() as u64).to_le_bytes());
        hasher.update(relative.as_bytes());
        hasher.update(&(contents.len() as u64).to_le_bytes());
        hasher.update(contents);
    }
    assert_eq!(
        kata_agent_nanocode::CODE_MODE_ENGINE_DIGEST,
        hasher.finalize().to_hex().as_str()
    );
}
