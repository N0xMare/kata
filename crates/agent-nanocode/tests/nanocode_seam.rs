//! The pins kata's nanocode embedding stands on, read out of nanocode itself and out
//! of `Cargo.lock`, never out of a kata adapter.
//!
//! nanocode is pinned by git rev, and its host seam and the tools each backend
//! registers over it move between commits, so a bump must go red HERE before it
//! reaches a capsule:
//!
//! * `host_sets_are_the_pinned_names` refuses a rev whose host tool constructors
//!   register any tool name other than `HOST_SET_CODEX` / `HOST_SET_CLAUDE`, or miss
//!   one of them. It builds each backend's host tools over a seam double, so the
//!   names are nanocode's, not a copy of kata's list, and it compares both backends
//!   before it fails (`host_set_drift`, pinned by
//!   `host_set_drift_names_every_moved_backend`): one `host tool-set drift:` line per
//!   moved set, naming what was added and what is missing. The L2 nightly's nanocode drift step quotes those
//!   lines (`scripts/nightly.sh`, `nanocode_drift`).
//! * `nanocode_rev_matches_the_lockfile` refuses a lockfile in which any package
//!   named `nanocode*`, or any git package from the nanocode repository in any
//!   spelling (`is_nanocode_source`), has a source other than exactly
//!   `git+https://github.com/nanocodexyz/nanocode?rev=<NANOCODE_REV>#<NANOCODE_REV>`
//!   (a `VENDORED_CRATES` crate instead has exactly one entry, a path package), and
//!   a lockfile missing one of the crates kata depends on directly. That the path
//!   package's bytes are upstream at `NANOCODE_REV` plus kata's patch is
//!   `scripts/nanocode-vendor.py check`'s refusal, not this file's.
//!   `nanocode_source_is_recognized_in_every_spelling` pins which spellings count.

use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};

use kata_agent_nanocode::{HOST_SET_CLAUDE, HOST_SET_CODEX, NANOCODE_REV};
use nanocode_backend_codex::Tools;
use nanocode_process_contracts::{
    ExecCommand, ExecCommandResult, FileHost, ForegroundCommand, ForegroundExecutor,
    ForegroundOutput, ProcessFuture, ShellExecutor, WriteStdin,
};

const REFUSED: &str = "the seam double serves no call: building a tool set must make none";

/// A seam double that serves no call: its `FileHost` and `ForegroundExecutor` verbs
/// return `Err(REFUSED)`, its `ShellExecutor` verbs a failed result. Building the
/// tool sets is synchronous and polls none of its futures.
struct RefusingSeam;

impl FileHost for RefusingSeam {
    fn read<'a>(
        &'a self,
        _path: &'a std::path::Path,
    ) -> ProcessFuture<'a, Result<Option<String>, String>> {
        Box::pin(async { Err(REFUSED.to_owned()) })
    }

    fn write<'a>(
        &'a self,
        _path: &'a std::path::Path,
        _contents: &'a str,
    ) -> ProcessFuture<'a, Result<(), String>> {
        Box::pin(async { Err(REFUSED.to_owned()) })
    }

    fn remove<'a>(&'a self, _path: &'a std::path::Path) -> ProcessFuture<'a, Result<(), String>> {
        Box::pin(async { Err(REFUSED.to_owned()) })
    }
}

impl ShellExecutor for RefusingSeam {
    fn execute<'a>(
        &'a self,
        _command: ExecCommand,
        _workspace: &'a std::path::Path,
    ) -> ProcessFuture<'a, ExecCommandResult> {
        Box::pin(async { ExecCommandResult::failed(Duration::ZERO, REFUSED.to_owned()) })
    }

    fn write_stdin(&self, _request: WriteStdin) -> ProcessFuture<'_, ExecCommandResult> {
        Box::pin(async { ExecCommandResult::failed(Duration::ZERO, REFUSED.to_owned()) })
    }

    fn terminate_all(&self) -> ProcessFuture<'_, ()> {
        Box::pin(async {})
    }
}

impl ForegroundExecutor for RefusingSeam {
    fn execute<'a>(
        &'a self,
        _command: ForegroundCommand<'a>,
    ) -> ProcessFuture<'a, Result<ForegroundOutput, String>> {
        Box::pin(async { Err(REFUSED.to_owned()) })
    }
}

/// Every registered name, sorted, duplicates kept: a name registered twice is a
/// different set from the pinned one.
fn registered_names(tools: &Tools) -> Vec<String> {
    let mut names: Vec<String> = tools
        .registered_tools()
        .map(|tool| tool.definition().name().to_owned())
        .collect();
    names.sort();
    names
}

fn sorted<const N: usize>(pinned: [&str; N]) -> Vec<String> {
    let mut names: Vec<String> = pinned.iter().map(|name| (*name).to_owned()).collect();
    names.sort();
    names
}

/// One backend's host tool set against its pin, as the line the nightly's nanocode
/// drift report quotes: the names nanocode registers that the pin lacks (`added`)
/// and the pinned names it does not register (`missing`), each as a multiset, so a
/// name registered twice is one `added`. `None` when the two are the same set.
fn tool_set_drift(
    backend: &str,
    pin: &str,
    registered: &[String],
    pinned: &[String],
) -> Option<String> {
    let mut missing = pinned.to_vec();
    let mut added = Vec::new();
    for name in registered {
        match missing.iter().position(|pinned| pinned == name) {
            Some(index) => {
                missing.remove(index);
            }
            None => added.push(name.clone()),
        }
    }
    (!added.is_empty() || !missing.is_empty()).then(|| {
        format!(
            "host tool-set drift: {backend} host tools at nanocode {NANOCODE_REV} are not {pin}: \
             added {added:?}, missing {missing:?}"
        )
    })
}

/// Both backends' host tool sets against their pins, compared before anything fails,
/// so a rev that moves both sets names both: one `host tool-set drift:` line each.
fn host_set_drift(codex: &[String], claude: &[String]) -> Vec<String> {
    [
        tool_set_drift("codex", "HOST_SET_CODEX", codex, &sorted(HOST_SET_CODEX)),
        tool_set_drift(
            "claude",
            "HOST_SET_CLAUDE",
            claude,
            &sorted(HOST_SET_CLAUDE),
        ),
    ]
    .into_iter()
    .flatten()
    .collect()
}

#[test]
fn host_sets_are_the_pinned_names() {
    let seam = Arc::new(RefusingSeam);
    let workspace = PathBuf::from("/work");

    let codex = nanocode_backend_codex::builtin_tools::host_tools(
        workspace.clone(),
        Arc::clone(&seam) as Arc<dyn FileHost>,
        Arc::clone(&seam) as Arc<dyn ShellExecutor>,
    )
    .expect("nanocode's codex host tools build over the seam double");
    let claude = nanocode_backend_claude::host_tools(
        workspace,
        Arc::clone(&seam) as Arc<dyn FileHost>,
        seam as Arc<dyn ForegroundExecutor>,
    )
    .expect("nanocode's claude host tools build over the seam double");

    let drift = host_set_drift(&registered_names(&codex), &registered_names(&claude));
    assert!(drift.is_empty(), "{}", drift.join("\n"));
}

#[test]
fn host_set_drift_names_every_moved_backend() {
    let codex = sorted(HOST_SET_CODEX);
    let claude = sorted(HOST_SET_CLAUDE);
    assert_eq!(host_set_drift(&codex, &claude), Vec::<String>::new());

    let mut moved_codex = codex.clone();
    moved_codex.push("planted_codex".to_owned());
    let mut moved_claude = claude.clone();
    let dropped = moved_claude.remove(0);
    moved_claude.push("planted_claude".to_owned());
    assert_eq!(
        host_set_drift(&moved_codex, &moved_claude),
        vec![
            format!(
                "host tool-set drift: codex host tools at nanocode {NANOCODE_REV} are not \
                 HOST_SET_CODEX: added [\"planted_codex\"], missing []"
            ),
            format!(
                "host tool-set drift: claude host tools at nanocode {NANOCODE_REV} are not \
                 HOST_SET_CLAUDE: added [\"planted_claude\"], missing [{dropped:?}]"
            ),
        ]
    );
}

#[test]
fn tool_set_drift_names_what_moved_and_nothing_when_nothing_did() {
    let names =
        |list: &[&str]| -> Vec<String> { list.iter().map(|name| (*name).to_owned()).collect() };
    assert_eq!(
        tool_set_drift("codex", "PIN", &names(&["a", "b"]), &names(&["a", "b"])),
        None
    );
    assert_eq!(
        tool_set_drift(
            "codex",
            "PIN",
            &names(&["a", "c", "c"]),
            &names(&["a", "b", "c"])
        ),
        Some(format!(
            "host tool-set drift: codex host tools at nanocode {NANOCODE_REV} are not PIN: \
             added [\"c\"], missing [\"b\"]"
        ))
    );
}

/// The repository every nanocode package must come from, as cargo writes a git
/// source: `git+<url>?rev=<manifest rev>#<resolved commit>`.
const NANOCODE_REPOSITORY: &str = "https://github.com/nanocodexyz/nanocode";

/// The crates kata depends on directly; everything else nanocode brings in is
/// theirs. `nanocode-code-mode-engine` is the vendored one, a path dependency.
const DIRECT_CRATES: [&str; 5] = [
    "nanocode-backend-claude",
    "nanocode-backend-codex",
    "nanocode-code-mode-engine",
    "nanocode-process-contracts",
    "nanocode-sync",
];

/// The nanocode crates the workspace `[patch]` routes to an in-tree copy under
/// `vendor/`. Each must resolve to exactly one path package: a git entry for one
/// means some dependency on it escaped the `[patch]` and builds the unpatched
/// upstream copy.
const VENDORED_CRATES: [&str; 1] = ["nanocode-code-mode-engine"];

/// How `nanocode_rev_matches_the_lockfile` spells a package with no `source`.
const PATH_PACKAGE: &str = "<no source: a path package>";

#[test]
fn nanocode_rev_matches_the_lockfile() {
    let lock_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock");
    let lock: toml::Table = std::fs::read_to_string(&lock_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", lock_path.display()))
        .parse()
        .unwrap_or_else(|error| panic!("parse {}: {error}", lock_path.display()));
    let packages = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .expect("Cargo.lock has a [[package]] array");

    let pinned = format!("git+{NANOCODE_REPOSITORY}?rev={NANOCODE_REV}#{NANOCODE_REV}");
    let mut nanocode: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for package in packages {
        let name = package
            .get("name")
            .and_then(toml::Value::as_str)
            .expect("every Cargo.lock package has a name");
        let source = package
            .get("source")
            .and_then(toml::Value::as_str)
            .unwrap_or(PATH_PACKAGE);
        if name.starts_with("nanocode") || is_nanocode_source(source) {
            nanocode
                .entry(name.to_owned())
                .or_default()
                .push(source.to_owned());
        }
    }

    let off_pin: Vec<String> = nanocode
        .iter()
        .filter(|(name, sources)| {
            let wanted = if VENDORED_CRATES.contains(&name.as_str()) {
                PATH_PACKAGE
            } else {
                pinned.as_str()
            };
            sources.as_slice() != [wanted]
        })
        .map(|(name, sources)| format!("{name} = {sources:?}"))
        .collect();
    assert!(
        off_pin.is_empty(),
        "Cargo.lock resolves nanocode packages off NANOCODE_REV ({pinned}), or a vendored \
         one ({VENDORED_CRATES:?}) other than as one path package:\n{}",
        off_pin.join("\n")
    );
    let missing: Vec<&str> = DIRECT_CRATES
        .into_iter()
        .filter(|name| !nanocode.contains_key(*name))
        .collect();
    assert!(
        missing.is_empty(),
        "Cargo.lock has no entry for {missing:?}; kata depends on them directly"
    );
}

/// Whether a `Cargo.lock` source is a git checkout of the nanocode repository, in
/// any spelling cargo accepts for it: the URL is compared as `host/path`, without
/// its scheme, user, query or fragment, ignoring letter case (GitHub's are
/// case-insensitive), a trailing `/` and a `.git` suffix.
fn is_nanocode_source(source: &str) -> bool {
    source
        .strip_prefix("git+")
        .and_then(repository_identity)
        .is_some_and(|identity| repository_identity(NANOCODE_REPOSITORY) == Some(identity))
}

/// `host/path` of a git URL, lowercased, with no user, trailing `/` or `.git`.
fn repository_identity(url: &str) -> Option<String> {
    let url = url.split(['?', '#']).next()?.to_ascii_lowercase();
    let (_scheme, rest) = url.split_once("://")?;
    let (authority, path) = rest.split_once('/')?;
    let host = authority.rsplit('@').next()?;
    let path = path.trim_end_matches('/');
    let path = path
        .strip_suffix(".git")
        .unwrap_or(path)
        .trim_end_matches('/');
    Some(format!("{host}/{path}"))
}

#[test]
fn nanocode_source_is_recognized_in_every_spelling() {
    for spelling in [
        "git+https://github.com/nanocodexyz/nanocode?rev=deadbeef#deadbeef",
        "git+https://github.com/nanocodexyz/nanocode.git?rev=deadbeef#deadbeef",
        "git+https://github.com/nanocodexyz/nanocode/?rev=deadbeef#deadbeef",
        "git+https://github.com/nanocodexyz/nanocode.git/#deadbeef",
        "git+https://GitHub.com/NanoCodeXYZ/NanoCode#deadbeef",
        "git+http://github.com/nanocodexyz/nanocode#deadbeef",
        "git+ssh://git@github.com/nanocodexyz/nanocode.git#deadbeef",
    ] {
        assert!(
            is_nanocode_source(spelling),
            "{spelling} is the nanocode repository"
        );
    }
    for other in [
        "git+https://github.com/nanocodexyz/nanocode-fork#deadbeef",
        "git+https://github.com/someone/nanocode#deadbeef",
        "git+https://gitlab.com/nanocodexyz/nanocode#deadbeef",
        "registry+https://github.com/rust-lang/crates.io-index",
        "<no source: a path package>",
    ] {
        assert!(
            !is_nanocode_source(other),
            "{other} is not the nanocode repository"
        );
    }
}

// Small suites folded into this binary so each costs no link of its own. Each
// keeps its module, so its tests are named `<module>::<test>` here.
#[path = "nanocode_seam/code_mode_engine_digest.rs"]
mod code_mode_engine_digest;
