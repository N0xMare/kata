//! What a shipped pack names in this repository exists where the pack says.
//!
//! The packs under `workflows/` run kata's own checks against kata's own tree: a
//! validate stage runs `just validate-crate <crate> <filter>`, a factory pack lists
//! `just test-one-crate <crate> <filter>` among its validation commands, an audit
//! prompt tells its model which file to read. When code moves between crates those
//! names go stale without a load error: nextest exits 4 on a filter that selects no
//! test, so every run of that stage fails, and a model told to read a file that is gone
//! grades a vacuum. These cells read the packs as TEXT, and the workspace through cargo
//! and the filesystem, never through kata's evaluator.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use regex::Regex;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate lives under <repo>/crates/program")
        .to_path_buf()
}

/// Every file under `root` matching `pattern` (a glob relative to `root`).
fn files(root: &Path, pattern: &str) -> Vec<PathBuf> {
    let pattern = root.join(pattern);
    glob::glob(pattern.to_str().expect("a UTF-8 repo path"))
        .expect("a valid glob")
        .map(|entry| entry.expect("a readable directory entry"))
        .collect()
}

/// Every shipped pack's source text, keyed by its repo-relative path.
fn shipped_packs(root: &Path) -> BTreeMap<String, String> {
    let packs: BTreeMap<String, String> = files(root, "workflows/**/*.star")
        .into_iter()
        .map(|path| {
            let source = std::fs::read_to_string(&path).expect("a readable pack");
            let relative = path.strip_prefix(root).expect("a pack under the repo");
            (relative.display().to_string(), source)
        })
        .collect();
    assert!(
        packs.contains_key("workflows/std/kata-loop-lite.star"),
        "the pack walk found no workflows/std/kata-loop-lite.star: {:?}",
        packs.keys()
    );
    packs
}

/// Each workspace package's directory under its package name, and each package at
/// `crates/<dir>` under `<dir>`: the justfile's crate recipes accept either spelling,
/// cargo's `-p` the package name alone.
struct WorkspacePackages {
    by_name: BTreeMap<String, PathBuf>,
    by_crates_dir: BTreeMap<String, PathBuf>,
}

fn workspace_packages(root: &Path) -> WorkspacePackages {
    let output = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--locked",
            "--offline",
        ])
        .current_dir(root)
        .output()
        .expect("cargo metadata runs");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata is JSON");
    let mut packages = WorkspacePackages {
        by_name: BTreeMap::new(),
        by_crates_dir: BTreeMap::new(),
    };
    for package in metadata["packages"].as_array().unwrap() {
        let directory = Path::new(package["manifest_path"].as_str().unwrap())
            .parent()
            .expect("a manifest has a directory")
            .to_path_buf();
        if directory.parent().and_then(Path::file_name) == Some(OsStr::new("crates")) {
            let name = directory.file_name().unwrap().to_str().unwrap().to_owned();
            packages.by_crates_dir.insert(name, directory.clone());
        }
        packages
            .by_name
            .insert(package["name"].as_str().unwrap().to_owned(), directory);
    }
    packages
}

/// The `fn` and `mod` names a package's Rust sources declare (`src/`, `tests/`,
/// `benches/`), read as text.
fn declared_items(package: &Path) -> (BTreeSet<String>, BTreeSet<String>) {
    let item = Regex::new(r"\b(fn|mod)\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)").unwrap();
    let mut functions = BTreeSet::new();
    let mut modules = BTreeSet::new();
    for directory in ["src", "tests", "benches"] {
        for path in files(package, &format!("{directory}/**/*.rs")) {
            let source = std::fs::read_to_string(&path).expect("a readable Rust source");
            for captures in item.captures_iter(&source) {
                let name = captures[2].to_owned();
                if &captures[1] == "fn" {
                    functions.insert(name);
                } else {
                    modules.insert(name);
                }
            }
        }
    }
    (functions, modules)
}

/// The refused set: a crate command in a shipped pack's text —
/// `just test-crate|lint-crate <package>`, `just test-one-crate|validate-crate
/// <package> [<filter>]`, `cargo nextest run -p <package> [<filter>]`, or any other
/// `cargo <subcommand> -p <package>` — whose `<package>` names no workspace package
/// (by package name; a `just` recipe also by `crates/<dir>`, as it accepts), or whose
/// `<filter>` names nothing that package's Rust sources (`src/`, `tests/`, `benches/`)
/// declare: a `::`-path filter (`library::`) needs a `mod` for every segment, a bare
/// filter (`starlark_eval`) a `fn` or a `mod` of that name. It reads declarations as
/// text, so a filter naming a declared `fn` that is not a test passes it; a filter
/// that names no whole declared item (a substring of test names nextest would still
/// match) is refused. A placeholder (`<crate>`, `...`) is not a package name and is
/// not read.
///
/// **Would red if:** a shipped pack ran `just validate-crate kata-workflow
/// starlark_eval` after the frontend's tests moved to kata-program.
#[test]
fn shipped_pack_crate_commands_name_the_package_that_declares_their_filter() {
    let root = repo_root();
    let packages = workspace_packages(&root);
    let package = r"([a-z][a-z0-9_-]*)";
    let filter = r"(?: ([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z0-9_]*)*))?";
    // Each command form, and whether it takes a `crates/<dir>` name too.
    let commands = [
        (
            Regex::new(&format!(r"\bjust (?:test-crate|lint-crate) {package}")).unwrap(),
            true,
        ),
        (
            Regex::new(&format!(
                r"\bjust (?:test-one-crate|validate-crate) {package}{filter}"
            ))
            .unwrap(),
            true,
        ),
        (
            Regex::new(&format!(r"\bcargo nextest run -p {package}{filter}")).unwrap(),
            false,
        ),
        (
            Regex::new(&format!(r"\bcargo [a-z-]+ -p {package}")).unwrap(),
            false,
        ),
    ];
    let mut declared = BTreeMap::new();
    let mut checked = BTreeSet::new();
    let mut refused = Vec::new();
    for (pack, source) in shipped_packs(&root) {
        for (command, takes_crates_dir) in &commands {
            for captures in command.captures_iter(&source) {
                let name = captures[1].to_owned();
                let filter = captures.get(2).map(|filter| filter.as_str().to_owned());
                checked.insert((name.clone(), filter.clone()));
                let directory = packages.by_name.get(&name).or_else(|| {
                    packages
                        .by_crates_dir
                        .get(&name)
                        .filter(|_| *takes_crates_dir)
                });
                let Some(directory) = directory else {
                    refused.push(format!("{pack}: `{}` names no package", &captures[0]));
                    continue;
                };
                let Some(filter) = filter else { continue };
                let (functions, modules) = declared
                    .entry(directory.clone())
                    .or_insert_with(|| declared_items(directory));
                let segments: Vec<&str> = filter
                    .split("::")
                    .filter(|segment| !segment.is_empty())
                    .collect();
                let (found, wanted) = if filter.contains("::") {
                    let found = segments.iter().all(|segment| modules.contains(*segment));
                    (found, "mod for every segment of")
                } else {
                    let found = functions.contains(&filter) || modules.contains(&filter);
                    (found, "fn or mod")
                };
                if !found {
                    refused.push(format!(
                        "{pack}: `{}`: {name} declares no {wanted} `{filter}`",
                        &captures[0]
                    ));
                }
            }
        }
    }
    // The walk is not vacuous: it read a filtered crate command.
    assert!(
        checked.iter().any(|(_, filter)| filter.is_some()),
        "no shipped pack command with a test filter was read: {checked:?}"
    );
    assert_eq!(refused, Vec::<String>::new());
}

/// The refused set: a repository path a shipped pack's text names — beginning
/// `crates/`, `bin/`, `scripts/`, `docs/`, `workflows/` or `test/` and ending in a file
/// extension — that does not exist in this checkout. A pack names such a path in a
/// prompt (a file its model is told to read) or in a comment citing where a rule
/// lives; either way a moved file leaves it naming nothing. A path the regex does not
/// see whole (wrapped across a line, or a brace or glob form) is not read.
///
/// **Would red if:** a shipped pack told its model to read
/// `crates/workflow/src/library.rs` after the workflow library moved to kata-program.
#[test]
fn shipped_pack_repo_paths_exist() {
    let root = repo_root();
    let path = Regex::new(
        r"\b(?:crates|bin|scripts|docs|workflows|test)/[A-Za-z0-9_./-]*[A-Za-z0-9_]\.[a-z]+\b",
    )
    .unwrap();
    let mut checked = 0_usize;
    let mut missing = Vec::new();
    for (pack, source) in shipped_packs(&root) {
        for named in path.find_iter(&source) {
            checked += 1;
            if !root.join(named.as_str()).exists() {
                missing.push(format!("{pack}: {}", named.as_str()));
            }
        }
    }
    assert!(checked > 0, "no shipped pack names a repository path");
    assert_eq!(missing, Vec::<String>::new());
}

// Small suites folded into this binary so each costs no link of its own. Each
// keeps its module, so its tests are named `<module>::<test>` here.
#[path = "shipped_pack_references/manifest.rs"]
mod manifest;
