//! Guard: no doc, comment, or emitted string may offer `kata-client <verb>` as
//! an operator's recourse, because no such executable is ever built.
//!
//! # Why a guard and not a one-time sweep
//!
//! A command naming a binary nothing builds is easy to write — an operator
//! output handle once emitted one — and once written it spreads into rustdoc
//! and comments, including `pub` rustdoc that reaches docs.rs. A one-time sweep
//! leaves nothing stopping the next site: `just lint` cannot see a wrong command
//! inside a doc comment, and the crate name makes `kata-client promote` read as
//! obviously right.
//!
//! The real CLI is the `kata` binary from `bin/kata`. The mapping, each
//! verified against `kata <cmd> --help`:
//! `promote`/`park`/`cancel`/`current` → `kata run <verb>`; `version` → `kata
//! version`; `watch` → `kata watch`; `wait-events` → `kata events --exit-on`.

use std::path::{Path, PathBuf};

/// This file, relative to the repository. It quotes the very strings it forbids.
const SELF_PATH: &str = "crates/client/tests/lib_tests/phantom_binary_guard.rs";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("client crate lives under <repo>/crates/client")
        .to_path_buf()
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("readable directory") {
        let path = entry.expect("readable entry").path();
        if path.is_dir() {
            // `target/` holds generated sources that are not ours to police.
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            rust_sources(&path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// Backticked command spans beginning `kata-client `, which is how a command is
/// written in this corpus. Prose like "the kata-client SDK" carries no
/// backticks and names no command, so it is not a hit.
fn phantom_commands(body: &str) -> Vec<String> {
    let mut hits = Vec::new();
    let mut rest = body;
    while let Some(start) = rest.find("`kata-client ") {
        let after = &rest[start + 1..];
        if let Some(end) = after.find('`') {
            hits.push(after[..end].to_string());
            rest = &after[end..];
        } else {
            rest = after;
        }
    }
    hits
}

#[test]
fn no_source_offers_a_kata_client_subcommand_as_operator_recourse() {
    let root = workspace_root();
    let mut sources = Vec::new();
    rust_sources(&root.join("crates"), &mut sources);
    rust_sources(&root.join("bin"), &mut sources);
    assert!(
        sources.len() > 100,
        "the walk found only {} sources — it is not reaching the workspace",
        sources.len()
    );

    let mut offenders: Vec<String> = Vec::new();

    for path in &sources {
        let rel = path
            .strip_prefix(&root)
            .expect("under the repository")
            .to_string_lossy()
            .to_string();
        // This file quotes the falsehood in order to name it, so it cannot be
        // subject to its own rule. Everything else is.
        if rel == SELF_PATH {
            continue;
        }
        let hits = phantom_commands(&std::fs::read_to_string(path).expect("readable source"));
        if !hits.is_empty() {
            offenders.push(format!("{rel}: {hits:?}"));
        }
    }

    assert!(
        offenders.is_empty(),
        "`crates/client` declares no `[[bin]]`, so no `kata-client` executable is ever built \
         or installed. These sites offer one as the operator's recourse; the real CLI is \
         `kata` (`kata run promote`, `kata run current`, `kata version`, `kata watch`, \
         `kata events --exit-on`):\n{}",
        offenders.join("\n")
    );
}

/// The premise the guard above rests on. If `crates/client` ever grows a
/// `[[bin]]`, `kata-client <verb>` stops being a falsehood and this whole guard
/// needs rethinking rather than silently passing.
#[test]
fn the_client_crate_still_declares_no_binary() {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("kata-client manifest is readable");
    assert!(
        !manifest.contains("[[bin]]"),
        "kata-client now declares a binary; the phantom-command guard's premise no longer holds"
    );
}
