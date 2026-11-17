//! THE `#[kata_timeout]` BUDGET CHECKER. The attribute arms a real-time watchdog whose
//! one job is to end a hung test BY NAME before nextest's anonymous slow-timeout kill
//! does. A budget at or above that kill never fires: the test dies as an unattributed
//! TIMEOUT, which is the triage cost the attribute exists to remove.
//!
//! This file refuses, and nothing else:
//!
//! 1. a `#[kata_timeout]` whose budget — its `secs`, or the macro's default read from the
//!    macro's own source — is at or above the kill nextest resolves for that test under
//!    the profile that runs it: `live-smoke` for an `#[ignore]`d test (every gate recipe
//!    that runs ignored cells with a kata_timeout runs them there), otherwise the first of
//!    `default`, `soak` and `measurement` whose `default-filter` admits it;
//! 2. a non-ignored `#[kata_timeout]` test that none of those three profiles admits —
//!    its kill cannot be resolved, so its budget cannot be checked;
//! 3. a `.rs` file carrying a `#[kata_timeout]` attribute that no workspace target's
//!    module tree reaches — a site the first rule could not see. The walk covers every
//!    regular `.rs` file under the repository root except build output, VCS metadata
//!    and the nested checkouts under `.worktrees` and `.claude` (`PRUNED_DIRS`), and
//!    follows no symlink;
//! 4. a site the checker cannot read: a `#[kata_timeout]` function with no test
//!    attribute, an attribute whose arguments are not one integer-literal `secs = N`
//!    (bare and `()` both read as the default, as the macro does), a target's crate root
//!    that does not parse, and a file naming `kata_timeout` that does not parse.
//!
//! WHAT IT CANNOT SEE, stated so it is not implied: a test run ad hoc under another
//! profile or through `--ignore-default-filter` (`just test-one`, `flake-check`), whose
//! kill is whatever that profile resolves; a `#[kata_timeout]` produced by another macro;
//! a module behind a `cfg` whose file is absent on this host. A test whose resolved
//! slow-timeout has no `terminate-after` has no kill, and any budget passes.
//!
//! It reads sources, `cargo metadata --no-deps` and `.config/nextest.toml` only; it builds
//! nothing and runs no test it names.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use common::nextest::{Filterset, TestIdentity, default_filters, kill_secs};
use common::repo_root;
use common::rust_tree::{
    ModuleDirs, ModuleSource, SourceCache, TargetKind, is_test_attribute, module_source, root_dirs,
    workspace_targets,
};

const NEXTEST_CONFIG_PATH: &str = ".config/nextest.toml";
const MACRO_SOURCE_PATH: &str = "crates/test-macros/src/lib.rs";
const DEFAULT_BUDGET_CONST: &str = "DEFAULT_SECS";
const IGNORED_PROFILE: &str = "live-smoke";
const PROFILES_BY_DEFAULT_FILTER: &[&str] = &["default", "soak", "measurement"];
/// Directories rule 3's walk never enters: build output, VCS metadata, and the nested
/// checkouts the main checkout holds (`.worktrees/gate-snapshot`, `.worktrees/nightly`,
/// `.claude/worktrees/*`), whose files belong to other checkouts' targets. The nested
/// checkouts match `scripts/source-tree-guard.py`'s `PRUNED`.
const PRUNED_DIRS: &[&str] = &[
    "target",
    ".git",
    ".jj",
    "node_modules",
    ".worktrees",
    ".claude",
];

/// One `#[kata_timeout]` test as one target compiles it.
#[derive(Debug)]
struct Site {
    package: String,
    target: String,
    kind: TargetKind,
    /// The test's path inside its binary, as nextest names it.
    test: String,
    file: PathBuf,
    budget: u64,
    ignored: bool,
}

impl Site {
    fn identity(&self) -> TestIdentity<'_> {
        TestIdentity {
            package: &self.package,
            binary_name: &self.target,
            binary_id: match self.kind {
                TargetKind::Lib => self.package.clone(),
                TargetKind::Bin => format!("{}::bin/{}", self.package, self.target),
                TargetKind::Test => format!("{}::{}", self.package, self.target),
            },
            kind: self.kind,
            test: &self.test,
        }
    }

    fn label(&self) -> String {
        format!(
            "{}::{} {} ({})",
            self.package,
            self.target,
            self.test,
            self.file.display()
        )
    }
}

fn is_kata_timeout(attr: &syn::Attribute) -> bool {
    attr.path()
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "kata_timeout")
}

/// The budget an attribute states, or `default` when it names none — bare or with empty
/// parentheses, both of which the macro reads as its default.
fn budget(attr: &syn::Attribute, default: u64) -> Result<u64, String> {
    let syn::Meta::List(list) = &attr.meta else {
        return Ok(default);
    };
    if list.tokens.is_empty() {
        return Ok(default);
    }
    let pair: syn::MetaNameValue = list
        .parse_args()
        .map_err(|error| format!("`{}`: {error}", list.tokens))?;
    if !pair.path.is_ident("secs") {
        return Err(format!("`{}` names no `secs`", list.tokens));
    }
    match &pair.value {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Int(secs),
            ..
        }) => secs
            .base10_parse()
            .map_err(|error| format!("`{}`: {error}", list.tokens)),
        _ => Err(format!("`{}` is not an integer literal", list.tokens)),
    }
}

/// The macro's default budget, read from its source rather than transcribed.
fn default_budget(root: &Path) -> u64 {
    let path = root.join(MACRO_SOURCE_PATH);
    let text = std::fs::read_to_string(&path).expect("reading the macro's source");
    let file = syn::parse_file(&text).expect("parsing the macro's source");
    file.items
        .iter()
        .find_map(|item| match item {
            syn::Item::Const(constant) if constant.ident == DEFAULT_BUDGET_CONST => {
                match &*constant.expr {
                    syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Int(secs),
                        ..
                    }) => secs.base10_parse().ok(),
                    _ => None,
                }
            }
            _ => None,
        })
        .unwrap_or_else(|| {
            panic!("{MACRO_SOURCE_PATH} defines no integer `{DEFAULT_BUDGET_CONST}`")
        })
}

/// Every `#[kata_timeout]` test the workspace's targets compile, and every file walked.
struct Walk {
    sites: Vec<Site>,
    reached: BTreeSet<PathBuf>,
    failures: Vec<String>,
}

struct TargetScope<'a> {
    package: &'a str,
    target: &'a str,
    kind: TargetKind,
    default: u64,
}

fn walk_items(
    cache: &mut SourceCache,
    walk: &mut Walk,
    scope: &TargetScope<'_>,
    items: &[syn::Item],
    file: &Path,
    dirs: &ModuleDirs,
    modules: &[String],
) {
    for item in items {
        match item {
            syn::Item::Fn(function) => {
                let Some(attr) = function.attrs.iter().find(|attr| is_kata_timeout(attr)) else {
                    continue;
                };
                let name = function.sig.ident.to_string();
                let test = modules
                    .iter()
                    .cloned()
                    .chain(std::iter::once(name.clone()))
                    .collect::<Vec<_>>()
                    .join("::");
                if !function.attrs.iter().any(is_test_attribute) {
                    walk.failures.push(format!(
                        "{}::{} {test} ({}): carries `#[kata_timeout]` but no test attribute",
                        scope.package,
                        scope.target,
                        file.display()
                    ));
                    continue;
                }
                match budget(attr, scope.default) {
                    Ok(budget) => walk.sites.push(Site {
                        package: scope.package.to_owned(),
                        target: scope.target.to_owned(),
                        kind: scope.kind,
                        test,
                        file: file.to_path_buf(),
                        budget,
                        ignored: function
                            .attrs
                            .iter()
                            .any(|attr| attr.path().is_ident("ignore")),
                    }),
                    Err(error) => walk.failures.push(format!(
                        "{}::{} {test} ({}): unreadable `#[kata_timeout]` budget {error}",
                        scope.package,
                        scope.target,
                        file.display()
                    )),
                }
            }
            syn::Item::Mod(declared) => {
                let mut inner_modules = modules.to_vec();
                inner_modules.push(declared.ident.to_string());
                match module_source(dirs, declared) {
                    ModuleSource::Inline(inline, inner) => {
                        walk_items(cache, walk, scope, inline, file, &inner, &inner_modules);
                    }
                    ModuleSource::File(child, inner) => {
                        // A file behind a `cfg` this host does not build may be absent; a
                        // `#[kata_timeout]` in a file no walk reaches is rule 3's to refuse.
                        let Ok(parsed) = cache.parse(&child) else {
                            continue;
                        };
                        let child_items = parsed.items.clone();
                        walk.reached.insert(child.clone());
                        walk_items(
                            cache,
                            walk,
                            scope,
                            &child_items,
                            &child,
                            &inner,
                            &inner_modules,
                        );
                    }
                }
            }
            _ => {}
        }
    }
}

fn walk_workspace(root: &Path) -> Walk {
    let default = default_budget(root);
    let mut cache = SourceCache::default();
    let mut walk = Walk {
        sites: Vec::new(),
        reached: BTreeSet::new(),
        failures: Vec::new(),
    };
    for (package, targets) in workspace_targets(root) {
        for target in targets {
            let Ok(parsed) = cache.parse(&target.src_path) else {
                walk.failures.push(format!(
                    "{package}::{}: its crate root {} does not parse",
                    target.name,
                    target.src_path.display()
                ));
                continue;
            };
            let items = parsed.items.clone();
            walk.reached.insert(target.src_path.clone());
            let scope = TargetScope {
                package: &package,
                target: &target.name,
                kind: target.kind,
                default,
            };
            let dirs = root_dirs(&target.src_path);
            walk_items(
                &mut cache,
                &mut walk,
                &scope,
                &items,
                &target.src_path,
                &dirs,
                &[],
            );
        }
    }
    walk
}

/// Every regular `.rs` file under `root` whose source carries a `#[kata_timeout]`
/// attribute on an item, or that does not parse while naming it. The walk follows no
/// symlink and skips [`PRUNED_DIRS`].
fn files_carrying_the_attribute(root: &Path) -> Vec<(PathBuf, Result<(), String>)> {
    fn carries(items: &[syn::Item]) -> bool {
        items.iter().any(|item| match item {
            syn::Item::Fn(function) => function.attrs.iter().any(is_kata_timeout),
            syn::Item::Mod(declared) => declared
                .content
                .as_ref()
                .is_some_and(|(_, inline)| carries(inline)),
            _ => false,
        })
    }
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|error| panic!("reading {}: {error}", dir.display()));
        for entry in entries {
            let entry = entry.expect("a directory entry");
            let path = entry.path();
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            let file_type = entry
                .file_type()
                .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
            if file_type.is_dir() {
                if !PRUNED_DIRS.contains(&name) {
                    pending.push(path);
                }
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            if path.extension().is_none_or(|extension| extension != "rs") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            if !text.contains("kata_timeout") {
                continue;
            }
            match syn::parse_file(&text) {
                Ok(file) if carries(&file.items) => found.push((path, Ok(()))),
                Ok(_) => {}
                Err(error) => found.push((path, Err(error.to_string()))),
            }
        }
    }
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found
}

/// The profile whose kill bounds `site`, per rule 1.
fn profile_for<'a>(site: &Site, defaults: &'a BTreeMap<String, Filterset>) -> Option<&'a str> {
    if site.ignored {
        return Some(IGNORED_PROFILE);
    }
    let identity = site.identity();
    PROFILES_BY_DEFAULT_FILTER.iter().copied().find_map(|name| {
        let (key, filter) = defaults
            .get_key_value(name)
            .or_else(|| defaults.get_key_value("default"))?;
        filter.matches(&identity).then_some(key.as_str())
    })
}

/// Rules 1 and 2 over `sites`.
fn budget_failures(sites: &[Site], config_text: &str) -> Vec<String> {
    let config: toml::Value = toml::from_str(config_text).expect("parsing .config/nextest.toml");
    let defaults = default_filters(config_text);
    let mut failures = Vec::new();
    for site in sites {
        let Some(profile) = profile_for(site, &defaults) else {
            failures.push(format!(
                "{}: no profile of {PROFILES_BY_DEFAULT_FILTER:?} admits it, so its kill — \
                 and so its {}s budget — cannot be resolved",
                site.label(),
                site.budget
            ));
            continue;
        };
        if let Some(kill) = kill_secs(&config, profile, &site.identity())
            && site.budget >= kill
        {
            failures.push(format!(
                "{}: `#[kata_timeout]` budget {}s is at or above the {kill}s kill the \
                 `{profile}` profile resolves for it, so the attributed timeout can never \
                 fire first — lower the budget, or give the test a deliberate \
                 slow-timeout override",
                site.label(),
                site.budget
            ));
        }
    }
    failures
}

fn report(failures: &[String]) -> String {
    let mut text = format!("{} refusal(s):\n", failures.len());
    for failure in failures {
        text.push_str("  - ");
        text.push_str(failure);
        text.push('\n');
    }
    text
}

#[test]
fn every_kata_timeout_budget_is_below_the_kill_of_the_profile_that_runs_it() {
    let root = repo_root();
    let walk = walk_workspace(&root);
    let config_text =
        std::fs::read_to_string(root.join(NEXTEST_CONFIG_PATH)).expect("reading nextest.toml");
    let mut failures = walk.failures;
    failures.extend(budget_failures(&walk.sites, &config_text));
    // A walk that found nothing would pass vacuously: the macro's own firing cells must be
    // among the sites, at the budgets their file states.
    let anchor = walk
        .sites
        .iter()
        .find(|site| site.package == "kata-test-utils" && site.target == "kata_timeout_tests")
        .map(|site| site.test.clone());
    assert!(
        anchor.is_some(),
        "the walk found no `#[kata_timeout]` in kata-test-utils' kata_timeout_tests; it \
         found {} site(s) in all",
        walk.sites.len()
    );
    assert!(failures.is_empty(), "{}", report(&failures));
}

#[test]
fn every_file_carrying_kata_timeout_is_reached_by_a_target() {
    let root = repo_root();
    let walk = walk_workspace(&root);
    let macro_source = root.join(MACRO_SOURCE_PATH);
    let mut failures = Vec::new();
    for (path, parsed) in files_carrying_the_attribute(&root) {
        if path == macro_source {
            continue;
        }
        match parsed {
            Err(error) => failures.push(format!(
                "{}: names `kata_timeout` and does not parse: {error}",
                path.display()
            )),
            Ok(()) if !walk.reached.contains(&path) => failures.push(format!(
                "{}: carries `#[kata_timeout]` but no workspace target's module tree reaches \
                 it, so its budgets are never checked",
                path.display()
            )),
            Ok(()) => {}
        }
    }
    assert!(failures.is_empty(), "{}", report(&failures));
}

// ─── the checker's own cells ─────────────────────────────────────────────────

fn site(test: &str, budget: u64, ignored: bool) -> Site {
    Site {
        package: "p".to_owned(),
        target: "t".to_owned(),
        kind: TargetKind::Test,
        test: test.to_owned(),
        file: PathBuf::from("t.rs"),
        budget,
        ignored,
    }
}

const SYNTHETIC_CONFIG: &str = r#"
[profile.default]
default-filter = 'not test(giant)'
slow-timeout = { period = "10s", terminate-after = 6 }

[[profile.default.overrides]]
filter = 'test(grouped)'
test-group = "heavy-io"

[[profile.default.overrides]]
filter = 'test(slow) | test(grouped)'
slow-timeout = { period = "30s", terminate-after = 4 }

[[profile.default.overrides]]
filter = 'test(warn_only)'
slow-timeout = "60s"

[profile.soak]
default-filter = 'test(giant)'

[[profile.soak.overrides]]
filter = 'test(giant)'
slow-timeout = { period = "1m", terminate-after = 10 }

[profile.live-smoke]
slow-timeout = { period = "60s", terminate-after = 5 }
"#;

#[test]
fn the_checker_refuses_a_budget_at_the_kill_and_admits_one_below_it() {
    let failures = budget_failures(
        &[
            site("plain_tie", 60, false),
            site("plain_below", 50, false),
            // The first override that SETS slow-timeout wins; one that only groups is
            // skipped for this setting.
            site("grouped_tie", 120, false),
            site("slow_below", 110, false),
            site("warn_only_any", 10_000, false),
            site("giant_tie", 600, false),
            site("giant_below", 590, false),
            site("live_tie", 300, true),
            site("live_below", 280, true),
        ],
        SYNTHETIC_CONFIG,
    );
    let refused: BTreeSet<&str> = failures
        .iter()
        .map(|failure| {
            failure
                .split_whitespace()
                .nth(1)
                .expect("a label names its test")
        })
        .collect();
    assert_eq!(
        refused,
        BTreeSet::from(["plain_tie", "grouped_tie", "giant_tie", "live_tie"]),
        "{}",
        report(&failures)
    );
}

#[test]
fn a_default_profile_override_outranks_a_profiles_own_slow_timeout() {
    // nextest 0.9.126, measured: profile overrides, then the default profile's overrides,
    // then the profile's own slow-timeout.
    let config: toml::Value = toml::from_str(SYNTHETIC_CONFIG).unwrap();
    let slow = site("slow_cell", 1, true);
    assert_eq!(
        kill_secs(&config, "live-smoke", &slow.identity()),
        Some(120)
    );
    let plain = site("plain_cell", 1, true);
    assert_eq!(
        kill_secs(&config, "live-smoke", &plain.identity()),
        Some(300)
    );
    let giant = site("giant", 1, false);
    assert_eq!(kill_secs(&config, "soak", &giant.identity()), Some(600));
    assert_eq!(kill_secs(&config, "default", &giant.identity()), Some(60));
}

#[test]
fn a_non_ignored_test_no_profile_admits_is_refused() {
    let config = r#"
[profile.default]
default-filter = 'not test(orphan)'
slow-timeout = { period = "10s", terminate-after = 6 }
"#;
    let failures = budget_failures(&[site("orphan", 1, false)], config);
    assert_eq!(failures.len(), 1, "{}", report(&failures));
    assert!(
        failures[0].contains("cannot be resolved"),
        "{}",
        failures[0]
    );
}

#[test]
fn the_attribute_walk_skips_nested_checkouts_and_keeps_the_workspaces_own_files() {
    // The main checkout nests the gate-snapshot and nightly worktrees under `.worktrees`
    // and agent worktrees under `.claude`: their files belong to other checkouts, whose
    // targets this workspace's walk never reaches.
    let root = tempfile::tempdir().expect("tempdir");
    let carrier = "#[kata_timeout]\n#[test]\nfn t() {}\n";
    let plant = |relative: &str| {
        let path = root.path().join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, carrier).unwrap();
        path
    };
    plant(".worktrees/gate-snapshot/crates/x/tests/t.rs");
    plant(".claude/worktrees/l/crates/x/tests/t.rs");
    // A symlinked directory is another path to files already walked, or to none of ours.
    std::os::unix::fs::symlink(
        root.path().join(".worktrees/gate-snapshot/crates/x"),
        root.path().join("linked"),
    )
    .unwrap();
    let orphan = plant("crates/x/tests/orphan/t.rs");
    let found: Vec<PathBuf> = files_carrying_the_attribute(root.path())
        .into_iter()
        .map(|(path, _)| path)
        .collect();
    assert_eq!(found, vec![orphan]);
}

#[test]
fn the_budget_reader_matches_the_macros_forms() {
    let read = |source: &str| {
        let function: syn::ItemFn = syn::parse_str(&format!("{source} fn t() {{}}")).unwrap();
        budget(&function.attrs[0], 7)
    };
    assert_eq!(read("#[kata_timeout]"), Ok(7));
    assert_eq!(read("#[kata_timeout()]"), Ok(7));
    assert_eq!(read("#[kata_timeout(secs = 30)]"), Ok(30));
    assert!(read("#[kata_timeout(30)]").is_err());
    assert!(read("#[kata_timeout(ms = 30)]").is_err());
}
