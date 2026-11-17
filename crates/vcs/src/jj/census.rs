//! The `oci` admission repository census for
//! [`JjBackend`].
//!
//! Under the `oci` profile jj is the sole VCS effect backend, and the capsule
//! materialization maps the workspace's committed tree bytes VERBATIM. A
//! repository whose features imply checkout-side work git does — a submodule's
//! populated tree, or a declaration that makes git write different bytes than
//! the committed blob — or whose object store is deliberately incomplete
//! (shallow boundary, promisor/partial-clone markers) cannot be served
//! faithfully, so the census refuses the submission at admission rather than
//! letting a capsule see a tree git never wrote.
//!
//! The attribute half of the refused set is exactly the declarations that
//! change the bytes git writes at checkout ON THIS PLATFORM: `filter` set
//! (clean/smudge — the mechanism Git LFS rides), `ident` set (`$Id$`
//! expansion), `working-tree-encoding` set (a charset conversion) and
//! `eol=crlf` (CRLF endings on checkout) — in any committed `.gitattributes`
//! at any depth or in `$GIT_DIR/info/attributes`, including via an `[attr]`
//! macro definition that sets one (git resolves macros stack-wide at use
//! time, so a definition applies to rules before it and in other sources).
//! `core.autocrlf=true` and `core.eol=crlf` in the repository's own config
//! convert the same way and refuse likewise; `core.attributesFile` points
//! declarations at a path the census cannot read and is refused for that.
//! Everything else an attribute file can say — `text`, `text=auto`, `-text`,
//! `binary`, `eol=lf`/`native`, `diff`, `merge`, `export-*`, `linguist-*`,
//! `-filter`/`!filter` — changes no checkout byte here and is admitted; so is
//! a `[filter "name"]` config section no declaration uses, and the mere
//! presence of `.gitattributes` or `info/attributes`.
//!
//! The census is a READ against two things and only those two:
//!
//! * the workspace's working-copy commit tree — the commit
//!   `create_workspace` checked out, whose tree is the base commit's by
//!   construction (jj's `check_out` makes `@` a child of the base carrying
//!   its tree unchanged, and nothing else has run); and
//! * the git store behind it, reached through jj's own
//!   [`jj_lib::git::get_git_backend`] so `gitdir:` indirections and
//!   linked-worktree layouts resolve the way git itself resolves them.
//!
//! It reads NO global configuration: git attributes are taken from the tree
//! itself and from `$GIT_DIR/info/attributes`, and config keys from the
//! repository's own `config` (with unconditional `include.path` followed,
//! since git honors it) — never `core.attributesFile`/`includeIf` plumbing
//! aimed outside the repository.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use jj_lib::backend::{FileId, TreeValue};
use jj_lib::merged_tree::MergedTree;
use jj_lib::repo::{Repo as _, StoreFactories};
use jj_lib::repo_path::RepoPathBuf;
use jj_lib::store::Store;
use jj_lib::workspace::{Workspace, default_working_copy_factories};
use kata_types::{KataError, KataResult};
use tokio::io::AsyncReadExt as _;

use kata_effects_contract::{ExecutionWorkspaceHandle, UnsupportedRepositoryFeature};

use super::JjBackend;

/// The most bytes of one attribute file the census will scan for
/// declarations. Attribute files are single-kilobyte scale; the cap only
/// bounds a pathological blob.
const MAX_ATTRIBUTE_FILE_BYTES: u64 = 1 << 20;

/// git's own `include.path` recursion bound — a chain deeper than this is
/// refused by git itself, so following further could only disagree.
const MAX_CONFIG_INCLUDE_DEPTH: usize = 10;

impl JjBackend {
    /// Run the repository census for a just-created execution workspace.
    ///
    /// `handle.path` is the workspace's root on disk; loading it recovers the
    /// shared repository and the workspace's own `@` — the commit
    /// `create_workspace` checked out over the selected base.
    ///
    /// Returns every finding in the refused set (see
    /// [`kata_effects_contract::UnsupportedRepositoryFeature`]); an empty
    /// `Vec` means the workspace admits. IO/decode failures of things the
    /// census MUST read (the tree, the workspace, the config file that exists
    /// but cannot be read) are `Err`, never a silent pass.
    pub(super) fn census_execution_workspace_repository(
        &self,
        handle: &ExecutionWorkspaceHandle,
    ) -> KataResult<Vec<UnsupportedRepositoryFeature>> {
        let settings = self.user_settings()?;
        let workspace = Workspace::load(
            &settings,
            &handle.path,
            &StoreFactories::default(),
            &default_working_copy_factories(),
        )
        .map_err(|err| {
            KataError::Internal(format!(
                "oci admission census could not load the execution workspace {}: {err}",
                handle.path.display()
            ))
        })?;
        let repo = Self::block_on(workspace.repo_loader().load_at_head()).map_err(|err| {
            KataError::Internal(format!(
                "oci admission census could not load the jj repository: {err}"
            ))
        })?;
        // The workspace's own name — `agent-<execution>` — read back from the
        // loaded workspace rather than re-derived, so the census follows the
        // handle it was given.
        let workspace_name = workspace.workspace_name().to_owned();
        let wc_commit = Self::workspace_commit(repo.as_ref(), &workspace_name)?;

        let mut findings = Vec::new();
        // Attribute-file BYTES are collected from every source the census
        // reads — the committed `.gitattributes` files and the repo's own
        // `info/attributes` — and scanned once at the end: git resolves
        // `[attr]` macros stack-wide at use time, so a declaration anywhere
        // expands everywhere.
        let mut attribute_sources = Vec::new();
        census_base_tree(
            repo.store().as_ref(),
            &wc_commit.tree(),
            &mut findings,
            &mut attribute_sources,
        )?;
        census_git_store(repo.as_ref(), &mut findings, &mut attribute_sources)?;
        emit_checkout_conversion_findings(&attribute_sources, &mut findings);
        Ok(findings)
    }
}

/// The tree half of the census: submodule declarations and the committed
/// attribute files' bytes, every one of them a committed fact of the base
/// tree.
///
/// `tree.entries()` walks every level; a conflicted entry counts every side —
/// a merge the base never resolved cannot be second-guessed for which side
/// git would have seen.
fn census_base_tree(
    store: &Store,
    tree: &MergedTree,
    findings: &mut Vec<UnsupportedRepositoryFeature>,
    attribute_sources: &mut Vec<(String, Vec<u8>)>,
) -> KataResult<()> {
    let mut root_gitmodules = false;
    let mut gitlinks = BTreeSet::new();
    // `.gitattributes` blobs in tree order (`entries()` walks sorted paths),
    // one FileId per conflicted side — the sides may declare different
    // conversions and every declaration is reported.
    let mut attribute_files: Vec<(RepoPathBuf, Vec<FileId>)> = Vec::new();
    for (path, value) in tree.entries() {
        let value = value.map_err(|err| {
            KataError::Internal(format!(
                "oci admission census could not read tree entry {}: {err}",
                path.as_internal_file_string()
            ))
        })?;
        for side in value.iter().flatten() {
            match side {
                TreeValue::GitSubmodule(_) => {
                    gitlinks.insert(path.as_internal_file_string().to_owned());
                }
                TreeValue::File { id, .. } => {
                    let internal = path.as_internal_file_string();
                    if internal == ".gitmodules" {
                        root_gitmodules = true;
                    }
                    if internal.rsplit('/').next() == Some(".gitattributes") {
                        match attribute_files.iter_mut().find(|(seen, _)| seen == &path) {
                            Some((_, ids)) => {
                                if !ids.contains(id) {
                                    ids.push(id.clone());
                                }
                            }
                            None => attribute_files.push((path.clone(), vec![id.clone()])),
                        }
                    }
                }
                // A symlink at either name applies nothing — measured: git's
                // attribute loader refuses in-tree `.gitattributes` symlinks
                // (ELOOP), so the file's declarations never take effect and
                // the capsule sees the symlink byte-for-byte the same way git
                // materialized it.
                _ => {}
            }
        }
    }

    if root_gitmodules {
        findings.push(UnsupportedRepositoryFeature::GitmodulesFile);
    }
    for path in gitlinks {
        findings.push(UnsupportedRepositoryFeature::GitSubmodule { path });
    }
    for (path, ids) in &attribute_files {
        for id in ids {
            let bytes = read_tree_file(store, path.as_ref(), id)?;
            attribute_sources.push((path.as_internal_file_string().to_owned(), bytes));
        }
    }
    Ok(())
}

/// Read one committed blob, capped at [`MAX_ATTRIBUTE_FILE_BYTES`].
fn read_tree_file(
    store: &Store,
    path: &jj_lib::repo_path::RepoPath,
    id: &FileId,
) -> KataResult<Vec<u8>> {
    let internal = path.as_internal_file_string().to_owned();
    JjBackend::block_on(async {
        let reader = store.read_file(path, id).await.map_err(|err| {
            KataError::Internal(format!(
                "oci admission census could not open `{internal}` in the base tree: {err}"
            ))
        })?;
        let mut bytes = Vec::new();
        reader
            .take(MAX_ATTRIBUTE_FILE_BYTES)
            .read_to_end(&mut bytes)
            .await
            .map_err(|err| {
                KataError::Internal(format!(
                    "oci admission census could not read `{internal}` from the base tree: {err}"
                ))
            })?;
        Ok::<_, KataError>(bytes)
    })
}

/// The git-store half of the census: the clone markers and the repository's
/// own attribute/config files, all under the git dir jj's backend reports
/// (linked-worktree `commondir` indirections resolved).
fn census_git_store(
    repo: &jj_lib::repo::ReadonlyRepo,
    findings: &mut Vec<UnsupportedRepositoryFeature>,
    attribute_sources: &mut Vec<(String, Vec<u8>)>,
) -> KataResult<()> {
    // A store with no git backend carries none of these features to refuse.
    let Ok(git_backend) = jj_lib::git::get_git_backend(repo.store()) else {
        return Ok(());
    };
    let git_dir = common_git_dir(git_backend.git_repo_path());
    if git_dir.join("shallow").is_file() {
        findings.push(UnsupportedRepositoryFeature::ShallowClone);
    }

    // `info/attributes` — the repository's own attribute file. git follows a
    // symlink here (unlike in-tree `.gitattributes`, measured), so anything
    // that exists and is not a directory applies — the file itself refuses
    // nothing; its DECLARATIONS are scanned like every other source.
    let info_attributes = git_dir.join("info").join("attributes");
    match fs::symlink_metadata(&info_attributes) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => match fs::read(&info_attributes) {
            Ok(bytes) => {
                attribute_sources.push(("$GIT_DIR/info/attributes".to_string(), bytes));
            }
            // A dangling symlink is an absent file — git's own read gets
            // ENOENT and applies nothing.
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            // Present-but-unreadable is a refusal, never a silent pass: a
            // `* filter=lfs` here is a declaration kata could not see while
            // git's checkout (same uid) still would.
            Err(err) => {
                return Err(KataError::Internal(format!(
                    "oci admission census could not read {}: {err}",
                    info_attributes.display()
                )));
            }
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(KataError::Internal(format!(
                "oci admission census could not stat {}: {err}",
                info_attributes.display()
            )));
        }
    }

    // The repository's own `config` carries the partial-clone record.
    // Unconditional `include.path` is honored (git honors it); conditional
    // `includeIf` is not — its conditions (`gitdir:`/`onbranch:` patterns)
    // are git's own expansion machinery, and a clone's own markers are
    // written into `config` itself by `git clone`.
    let config = git_dir.join("config");
    match fs::read(&config) {
        Ok(bytes) => {
            census_git_config(&bytes, &config, git_dir.as_path(), findings);
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(KataError::Internal(format!(
                "oci admission census could not read {}: {err}",
                config.display()
            )));
        }
    }
    Ok(())
}

/// The directory `shallow`, `config` and `info/` live in: the git dir itself,
/// or — for a linked worktree, whose git dir carries a `commondir` file
/// naming the shared one relative to it — that shared dir.
pub(super) fn common_git_dir(git_dir: &Path) -> PathBuf {
    fs::read_to_string(git_dir.join("commondir"))
        .ok()
        .map(|shared| git_dir.join(shared.trim()))
        .filter(|shared| shared.is_dir())
        .unwrap_or_else(|| git_dir.to_path_buf())
}

// ─── gitattributes parsing ──────────────────────────────────────────────────
//
// Enough of `gitattributes(5)` to find the declarations that change the
// bytes git writes at checkout on this platform — `filter`/`ident`/
// `working-tree-encoding` set, `eol=crlf` — and only those. Comment and
// blank lines are skipped, the first whitespace-separated token is the
// pattern (`"..."` quoting honored, C-style escapes unescaped), and each
// remaining token is an attribute state — `name` (set), `-name` (unset),
// `name=value` (set to value), `!name` (unspecified). Unset and unspecified
// forms declare nothing and produce no finding.
//
// `[attr]<name>` in the pattern position defines an attribute MACRO. git
// keeps macro definitions on the attribute STACK, not per file, and expands
// them when a rule SETS the name — so a definition applies to rules that
// precede it and to rules in every other source the census reads (both
// measured against `check-attr`). The scan therefore collects every macro
// definition across all sources before evaluating any rule, and expands a
// macro's list transitively with a visited-set for cycles. `-macro` and
// `!macro` do not expand (measured).

/// One attribute declaration from an attribute-file line.
#[derive(Debug, PartialEq, Eq)]
enum AttributeState {
    /// `name` — set to git's true value.
    Set,
    /// `-name` — unset.
    Unset,
    /// `!name` — unspecified.
    Unspecified,
    /// `name=value` — set to `value`.
    Value(String),
}

/// Parse one attribute-file line into `(pattern, attrs)`. `None` for blank
/// and comment lines; attribute tokens without a pattern are none at all.
fn parse_attribute_line(line: &str) -> Option<(String, Vec<(String, AttributeState)>)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (pattern, rest) = if let Some(quoted) = line.strip_prefix('"') {
        // C-style unquoting of the pattern, per gitattributes(5).
        let mut pattern = String::new();
        let mut chars = quoted.chars();
        let mut closed = false;
        while let Some(c) = chars.next() {
            match c {
                '"' => {
                    closed = true;
                    break;
                }
                '\\' => match chars.next() {
                    Some('n') => pattern.push('\n'),
                    Some('t') => pattern.push('\t'),
                    Some('r') => pattern.push('\r'),
                    Some(other) => pattern.push(other),
                    None => pattern.push('\\'),
                },
                _ => pattern.push(c),
            }
        }
        if !closed {
            // An unterminated quote is a malformed line git itself ignores.
            return None;
        }
        (pattern, chars.as_str())
    } else {
        match line.find(char::is_whitespace) {
            Some(split) => (line[..split].to_string(), &line[split..]),
            None => (line.to_string(), ""),
        }
    };
    let attrs = rest
        .split_whitespace()
        .filter_map(|token| {
            let (name, state) = if let Some(unset) = token.strip_prefix('-') {
                (unset, AttributeState::Unset)
            } else if let Some(unspecified) = token.strip_prefix('!') {
                (unspecified, AttributeState::Unspecified)
            } else if let Some((name, value)) = token.split_once('=') {
                (name, AttributeState::Value(value.to_string()))
            } else {
                (token, AttributeState::Set)
            };
            // git's attr-name alphabet; anything else is not an attribute.
            is_attribute_name(name).then(|| (name.to_string(), state))
        })
        .collect();
    Some((pattern, attrs))
}

/// Whether `name` parses as a git attribute name — git's attr alphabet.
fn is_attribute_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// Emit the refused finding for one `(name, state)` attribute token on
/// `pattern` in `source` — expanding a SET macro through `macros`, with
/// `visited` cutting macro cycles. Unset/unspecified states and names that
/// convert nothing are silent.
fn eval_attribute(
    name: &str,
    state: &AttributeState,
    pattern: &str,
    source: &str,
    macros: &std::collections::BTreeMap<String, Vec<(String, AttributeState)>>,
    visited: &mut BTreeSet<String>,
    findings: &mut Vec<UnsupportedRepositoryFeature>,
) {
    if matches!(state, AttributeState::Set)
        && let Some(expansion) = macros.get(name)
        && visited.insert(name.to_string())
    {
        for (name, state) in expansion {
            eval_attribute(name, state, pattern, source, macros, visited, findings);
        }
        return;
    }
    let conversion = match (name, state) {
        ("filter", AttributeState::Value(value)) => {
            push_unique(
                findings,
                UnsupportedRepositoryFeature::GitFilter {
                    source: source.to_string(),
                    pattern: pattern.to_string(),
                    value: Some(value.clone()),
                },
            );
            return;
        }
        ("filter", AttributeState::Set) => {
            push_unique(
                findings,
                UnsupportedRepositoryFeature::GitFilter {
                    source: source.to_string(),
                    pattern: pattern.to_string(),
                    value: None,
                },
            );
            return;
        }
        ("ident", AttributeState::Set) => Some("ident".to_string()),
        ("ident", AttributeState::Value(value)) => Some(format!("ident={value}")),
        ("working-tree-encoding", AttributeState::Set) => Some("working-tree-encoding".to_string()),
        ("working-tree-encoding", AttributeState::Value(value)) => {
            Some(format!("working-tree-encoding={value}"))
        }
        ("eol", AttributeState::Value(value)) => value
            .eq_ignore_ascii_case("crlf")
            .then(|| format!("eol={value}")),
        _ => None,
    };
    if let Some(attribute) = conversion {
        push_unique(
            findings,
            UnsupportedRepositoryFeature::GitCheckoutConversion {
                source: source.to_string(),
                pattern: pattern.to_string(),
                attribute,
            },
        );
    }
}

/// Scan every attribute source the census collected — committed
/// `.gitattributes` files and `$GIT_DIR/info/attributes` — and emit the
/// refused findings: [`UnsupportedRepositoryFeature::GitFilter`] for `filter`
/// declarations and [`UnsupportedRepositoryFeature::GitCheckoutConversion`]
/// for `ident`, `working-tree-encoding` and `eol=crlf`, each expanded through
/// the stack-wide `[attr]` macro definitions.
pub(crate) fn emit_checkout_conversion_findings(
    sources: &[(String, Vec<u8>)],
    findings: &mut Vec<UnsupportedRepositoryFeature>,
) {
    // Pass 1 — parse every line of every source; collect the macro
    // definitions (a later definition of one name wins, as git's
    // `all_macros` hashmap overwrites).
    let mut macros = std::collections::BTreeMap::new();
    let mut rules = Vec::new();
    for (source, bytes) in sources {
        for line in String::from_utf8_lossy(bytes).lines() {
            let Some((pattern, attrs)) = parse_attribute_line(line) else {
                continue;
            };
            if let Some(name) = pattern.strip_prefix("[attr]") {
                if is_attribute_name(name) {
                    macros.insert(name.to_string(), attrs);
                }
            } else {
                rules.push((source.clone(), pattern, attrs));
            }
        }
    }
    // Pass 2 — evaluate every rule's tokens, expanding macro uses.
    for (source, pattern, attrs) in rules {
        for (name, state) in attrs {
            eval_attribute(
                &name,
                &state,
                &pattern,
                &source,
                &macros,
                &mut BTreeSet::new(),
                findings,
            );
        }
    }
}

// ─── git config parsing ─────────────────────────────────────────────────────
//
// Enough of git's config grammar to name the census's config-level refused
// keys — the partial-clone markers, `core.attributesFile` and the two
// checkout-conversion keys:
// `[section]`, `[section.sub]` (the deprecated form — its subsection is
// lowercased like the section, per git's own normalization) and
// `[section "sub"]` (subsection kept verbatim), `key` (a bare key means
// `true`), `key = value`, `;`/`#` comments outside quotes, and `\` line
// continuation. git folds section and key names to lowercase; the quoted
// subsection keeps its case. Only the repository's own `config` and the
// files it `include.path`s are read — never a global file.

/// One config assignment: the section (lowercased), the quoted subsection
/// verbatim (or the dotted subsection lowercased), the key (lowercased) and
/// the value (`None` for the bare `key` true-form).
#[derive(Debug, PartialEq, Eq)]
struct ConfigEntry {
    section: String,
    subsection: Option<String>,
    key: String,
    value: Option<String>,
}

/// Strip `;`/`#` comments outside `"` quoting, and join `\`-terminated
/// continuations — git's lexical level.
fn config_logical_lines(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut pending = String::new();
    for physical in text.lines() {
        let mut out = String::new();
        let mut chars = physical.chars().peekable();
        let mut quoted = false;
        while let Some(c) = chars.next() {
            match c {
                '"' => {
                    quoted = !quoted;
                    out.push(c);
                }
                '\\' => {
                    out.push(c);
                    if let Some(next) = chars.next() {
                        out.push(next);
                    }
                }
                ';' | '#' if !quoted => break,
                _ => out.push(c),
            }
        }
        pending.push_str(out.trim_end());
        // A continuation is an ODD trailing count of backslashes.
        let trailing = pending.chars().rev().take_while(|c| *c == '\\').count();
        if trailing % 2 == 1 {
            pending.pop();
            continue;
        }
        lines.push(std::mem::take(&mut pending));
    }
    if !pending.trim().is_empty() {
        lines.push(pending);
    }
    lines
}

/// Parse one section header's interior: `name`, `name.sub` (deprecated —
/// everything lowercased) or `name "sub"` (subsection verbatim).
fn parse_config_section(inner: &str) -> Option<(String, Option<String>)> {
    let inner = inner.trim();
    if let Some((name, quoted)) = inner.split_once('"') {
        let name = name.trim().to_lowercase();
        let sub = quoted.trim_end().strip_suffix('"')?;
        Some((name, Some(sub.to_string())))
    } else if let Some((name, sub)) = inner.split_once('.') {
        Some((name.trim().to_lowercase(), Some(sub.trim().to_lowercase())))
    } else if inner.is_empty() {
        None
    } else {
        Some((inner.to_lowercase(), None))
    }
}

/// Parse config text into its entries. Malformed lines are skipped — a line
/// git cannot parse is not a marker this census can honor anyway.
fn parse_config_entries(text: &str) -> Vec<ConfigEntry> {
    let mut entries = Vec::new();
    let mut section: Option<(String, Option<String>)> = None;
    for line in config_logical_lines(text) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(inner) = line
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
        {
            section = parse_config_section(inner);
            continue;
        }
        let Some((section, subsection)) = section.clone() else {
            continue;
        };
        let (key, value) = match line.split_once('=') {
            Some((key, value)) => (key.trim().to_lowercase(), Some(unquote_config_value(value))),
            None => (line.trim().to_lowercase(), None),
        };
        if key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') && !key.is_empty() {
            entries.push(ConfigEntry {
                section,
                subsection,
                key,
                value,
            });
        }
    }
    entries
}

/// Undo git's `"` quoting and `\` escapes on a config value (the bare
/// essentials — `\n`/`\t`/`\b`/`\"`/`\\`), trimming what git trims.
fn unquote_config_value(value: &str) -> String {
    let value = value.trim();
    let mut out = String::new();
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => {}
            '\\' => match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('b') => out.push('\x08'),
                Some(other) => out.push(other),
                None => {}
            },
            _ => out.push(c),
        }
    }
    out.trim_end().to_string()
}

/// git's boolean interpretation of a config value: a bare key (no `=`) is
/// true; `true`/`yes`/`on`/nonzero numbers are true; `false`/`no`/`off`/`0`
/// and the empty string are false. `None` on an unparseable value — the
/// caller treats it as a finding anyway (a marker git cannot evaluate is not
/// proof the clone is complete).
fn config_value_is_true(value: Option<&str>) -> Option<bool> {
    match value {
        None => Some(true),
        Some(value) => {
            let lowered = value.to_lowercase();
            match lowered.as_str() {
                "" | "false" | "no" | "off" | "0" => Some(false),
                "true" | "yes" | "on" => Some(true),
                _ => lowered
                    .parse::<i64>()
                    .ok()
                    .map(|number| number != 0)
                    .or(None),
            }
        }
    }
}

/// Scan a repository `config` (and the files it `include.path`s) for the
/// census's config-level refused keys.
/// Resolve an `include.path` value the way git does — relative to the
/// including file's directory — then bound it to the repository's own
/// bookkeeping: `Some` only for a path still beneath `git_dir`. `~`-prefixed,
/// absolute, and `..`-climbing-above-`$GIT_DIR` values answer `None` (the
/// caller records the `GitConfigInclude` finding rather than reading a file
/// the census does not answer for).
fn resolve_include_path(dir: &Path, git_dir: &Path, include: &str) -> Option<PathBuf> {
    if include.starts_with('~') || Path::new(include).is_absolute() {
        return None;
    }
    let mut resolved = dir.to_path_buf();
    for component in include.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if !resolved.pop() {
                    return None;
                }
            }
            name => resolved.push(name),
        }
    }
    resolved.starts_with(git_dir).then_some(resolved)
}

fn census_git_config(
    bytes: &[u8],
    config_path: &Path,
    git_dir: &Path,
    findings: &mut Vec<UnsupportedRepositoryFeature>,
) {
    let mut visited = BTreeSet::new();
    let mut stack: Vec<(Vec<u8>, PathBuf)> = vec![(bytes.to_vec(), config_path.to_path_buf())];
    while let Some((bytes, path)) = stack.pop() {
        if !visited.insert(path.clone()) || visited.len() > MAX_CONFIG_INCLUDE_DEPTH {
            continue;
        }
        let Some(dir) = path.parent().map(Path::to_path_buf) else {
            continue;
        };
        for entry in parse_config_entries(&String::from_utf8_lossy(&bytes)) {
            match (
                entry.section.as_str(),
                entry.subsection.as_deref(),
                entry.key.as_str(),
            ) {
                // `core.attributesFile` points attribute declarations at a
                // path the census cannot reach — refused while non-empty (a
                // bare or empty value points at nothing).
                ("core", None, "attributesfile")
                    if entry.value.as_deref().is_some_and(|v| !v.is_empty()) =>
                {
                    push_unique(
                        findings,
                        UnsupportedRepositoryFeature::GitAttributesConfig {
                            key: "core.attributesFile".to_string(),
                        },
                    );
                }
                // `core.autocrlf = true` converts committed text bytes to
                // CRLF at checkout on this platform (measured); `input`,
                // `false` and a value git cannot evaluate do not. A bare
                // `autocrlf` is git's true form.
                ("core", None, "autocrlf")
                    if config_value_is_true(entry.value.as_deref()) == Some(true) =>
                {
                    push_unique(
                        findings,
                        UnsupportedRepositoryFeature::GitCheckoutConversionConfig {
                            key: "core.autocrlf".to_string(),
                        },
                    );
                }
                // `core.eol = crlf` forces CRLF at checkout for `text`-marked
                // files regardless of `autocrlf` (measured); `lf` and
                // `native` write the blob's own bytes.
                ("core", None, "eol")
                    if entry
                        .value
                        .as_deref()
                        .is_some_and(|v| v.eq_ignore_ascii_case("crlf")) =>
                {
                    push_unique(
                        findings,
                        UnsupportedRepositoryFeature::GitCheckoutConversionConfig {
                            key: "core.eol".to_string(),
                        },
                    );
                }
                ("extensions", None, "partialclone") => {
                    push_unique(
                        findings,
                        UnsupportedRepositoryFeature::PartialClone {
                            key: "extensions.partialclone".to_string(),
                        },
                    );
                }
                ("remote", Some(remote), "promisor")
                    if config_value_is_true(entry.value.as_deref()) != Some(false) =>
                {
                    push_unique(
                        findings,
                        UnsupportedRepositoryFeature::PartialClone {
                            key: format!("remote.{remote}.promisor"),
                        },
                    );
                }
                ("remote", Some(remote), "partialclonefilter") => {
                    push_unique(
                        findings,
                        UnsupportedRepositoryFeature::PartialClone {
                            key: format!("remote.{remote}.partialclonefilter"),
                        },
                    );
                }
                ("include", None, "path") => {
                    if let Some(include) = entry.value.as_deref() {
                        // git resolves `include.path` against the including
                        // file's directory, `~/`-prefixed against $HOME. The
                        // census reads the repository's own files and never a
                        // global one: anything that resolves outside the
                        // repository root (`~`, absolute, `..` above it) is a
                        // FINDING — git would honor a conversion key there
                        // and the census cannot answer for it — and a
                        // contained-but-unreadable include is a finding too
                        // (fail closed, like `config` itself). A missing
                        // include is git's no-op.
                        match resolve_include_path(&dir, git_dir, include) {
                            Some(include_path) => match fs::read(&include_path) {
                                Ok(bytes) => stack.push((bytes, include_path)),
                                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                                Err(err) => {
                                    push_unique(
                                        findings,
                                        UnsupportedRepositoryFeature::GitConfigInclude {
                                            path: format!("{include} (unreadable: {err})"),
                                        },
                                    );
                                }
                            },
                            None => {
                                push_unique(
                                    findings,
                                    UnsupportedRepositoryFeature::GitConfigInclude {
                                        path: format!("{include} (outside the repository)"),
                                    },
                                );
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

fn push_unique(
    findings: &mut Vec<UnsupportedRepositoryFeature>,
    finding: UnsupportedRepositoryFeature,
) {
    if !findings.contains(&finding) {
        findings.push(finding);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::VcsBackend;

    fn conversion_findings(text: &str) -> Vec<UnsupportedRepositoryFeature> {
        let mut findings = Vec::new();
        emit_checkout_conversion_findings(
            &[(".gitattributes".to_string(), text.as_bytes().to_vec())],
            &mut findings,
        );
        findings
    }

    #[test]
    fn attribute_lines_parse_the_git_grammar() {
        assert_eq!(parse_attribute_line(""), None);
        assert_eq!(parse_attribute_line("   "), None);
        assert_eq!(parse_attribute_line("# a comment"), None);
        assert_eq!(
            parse_attribute_line("*.bin filter=lfs"),
            Some((
                "*.bin".to_string(),
                vec![("filter".to_string(), AttributeState::Value("lfs".into()))]
            ))
        );
        assert_eq!(
            parse_attribute_line("*.bin filter -text !merge"),
            Some((
                "*.bin".to_string(),
                vec![
                    ("filter".to_string(), AttributeState::Set),
                    ("text".to_string(), AttributeState::Unset),
                    ("merge".to_string(), AttributeState::Unspecified),
                ]
            ))
        );
        // A quoted pattern keeps its space and unescapes C-style escapes.
        assert_eq!(
            parse_attribute_line("\"my dir/*.x\" filter=lfs"),
            Some((
                "my dir/*.x".to_string(),
                vec![("filter".to_string(), AttributeState::Value("lfs".into()))]
            ))
        );
        // `filter = lfs` is three tokens to git: `filter` SET, a `=` junk
        // token that parses to no attribute, `lfs` SET.
        assert_eq!(
            parse_attribute_line("*.bin filter = lfs"),
            Some((
                "*.bin".to_string(),
                vec![
                    ("filter".to_string(), AttributeState::Set),
                    ("lfs".to_string(), AttributeState::Set),
                ]
            ))
        );
        // A backslash inside a quoted pattern escapes the next char —
        // `\t` is a tab in the pattern, and a file named `a<TAB>b` matches it.
        assert_eq!(
            parse_attribute_line("\"a\\tb\" x"),
            Some((
                "a\tb".to_string(),
                vec![("x".to_string(), AttributeState::Set)]
            )),
            "the quoted-pattern \\ escape must decode before the matcher sees it"
        );
        // Attr names are git's alphabet — `foo$bar` is not an attribute.
        assert_eq!(
            parse_attribute_line("*.x ok-name_bad.name"),
            Some((
                "*.x".to_string(),
                vec![("ok-name_bad.name".to_string(), AttributeState::Set)]
            ))
        );
    }

    #[test]
    fn only_checkout_converting_declarations_produce_findings() {
        // The near-miss set: unset/unspecified forms, byte-preserving
        // declarations, and unknown attributes declare no conversion.
        let findings = conversion_findings(
            "# none of these convert checkout bytes\n\
             *.bin -filter\n\
             *.x !filter\n\
             *.t text eol=lf\n\
             *.n eol=native\n\
             *.b binary\n\
             *.d diff=rust\n\
             *.l linguist-documentation\n\
             *.e export-ignore\n\
             *.z -ident !working-tree-encoding\n",
        );
        assert_eq!(findings, Vec::new());

        // Bare and valued `filter` are clean/smudge hooks; `ident` expands
        // `$Id$`; `working-tree-encoding` re-encodes; `eol=crlf` writes CRLF.
        let findings = conversion_findings(
            "*.bin filter=lfs\n*.x filter\n*.i ident\n*.e working-tree-encoding=UTF-16\n*.c eol=crlf\n",
        );
        assert_eq!(
            findings,
            vec![
                UnsupportedRepositoryFeature::GitFilter {
                    source: ".gitattributes".to_string(),
                    pattern: "*.bin".to_string(),
                    value: Some("lfs".to_string()),
                },
                UnsupportedRepositoryFeature::GitFilter {
                    source: ".gitattributes".to_string(),
                    pattern: "*.x".to_string(),
                    value: None,
                },
                UnsupportedRepositoryFeature::GitCheckoutConversion {
                    source: ".gitattributes".to_string(),
                    pattern: "*.i".to_string(),
                    attribute: "ident".to_string(),
                },
                UnsupportedRepositoryFeature::GitCheckoutConversion {
                    source: ".gitattributes".to_string(),
                    pattern: "*.e".to_string(),
                    attribute: "working-tree-encoding=UTF-16".to_string(),
                },
                UnsupportedRepositoryFeature::GitCheckoutConversion {
                    source: ".gitattributes".to_string(),
                    pattern: "*.c".to_string(),
                    attribute: "eol=crlf".to_string(),
                },
            ]
        );
        // A BARE `working-tree-encoding` (Set, no value) re-encodes just as
        // its valued form does — git reads it as "the default conversion".
        assert_eq!(
            conversion_findings("*.x working-tree-encoding\n"),
            vec![UnsupportedRepositoryFeature::GitCheckoutConversion {
                source: ".gitattributes".to_string(),
                pattern: "*.x".to_string(),
                attribute: "working-tree-encoding".to_string(),
            }],
            "the bare Set form is the same finding as the valued form"
        );
        // `Filter` (capitalized) is not git's `filter` — attr names are
        // case-sensitive; `eol`'s VALUE is case-insensitive to git.
        assert_eq!(
            conversion_findings("*.x Filter=lfs\n*.y Eol=crlf\n"),
            Vec::<UnsupportedRepositoryFeature>::new()
        );
        assert_eq!(
            conversion_findings("*.y eol=CRLF\n"),
            vec![UnsupportedRepositoryFeature::GitCheckoutConversion {
                source: ".gitattributes".to_string(),
                pattern: "*.y".to_string(),
                attribute: "eol=CRLF".to_string(),
            }]
        );
    }

    #[test]
    fn attr_macros_expand_only_when_set() {
        // `[attr]m filter=lfs` defines `m`; only the Set form expands it, and
        // the expansion yields the refused finding at the USING pattern.
        let findings = conversion_findings("[attr]m filter=lfs\n*.bin m\n*.x -m\n*.y !m\n");
        assert_eq!(
            findings,
            vec![UnsupportedRepositoryFeature::GitFilter {
                source: ".gitattributes".to_string(),
                pattern: "*.bin".to_string(),
                value: Some("lfs".to_string()),
            }]
        );

        // A macro of only safe declarations expands to nothing refused.
        assert_eq!(
            conversion_findings("[attr]safe text eol=lf\n*.s safe\n"),
            Vec::<UnsupportedRepositoryFeature>::new()
        );

        // A self-referential macro cycle terminates on the visited set.
        let findings = conversion_findings("[attr]a b\n[attr]b a filter=x\n*.z a\n");
        assert_eq!(
            findings,
            vec![UnsupportedRepositoryFeature::GitFilter {
                source: ".gitattributes".to_string(),
                pattern: "*.z".to_string(),
                value: Some("x".to_string()),
            }]
        );

        // Definitions apply to rules BEFORE them — git resolves macros at use
        // time from the whole-file collection.
        let findings = conversion_findings("*.z m\n[attr]m filter=x\n");
        assert_eq!(
            findings,
            vec![UnsupportedRepositoryFeature::GitFilter {
                source: ".gitattributes".to_string(),
                pattern: "*.z".to_string(),
                value: Some("x".to_string()),
            }]
        );
    }

    #[test]
    fn config_entries_parse_sections_and_values() {
        let text = "[remote \"Origin\"]\n\tpromisor = true\n\
                    partialclonefilter = blob:none\n\
                    [remote.Mirror]\n\tpromisor = yes ; trailing comment\n\
                    [extensions]\n\tpartialClone = origin\n\
                    [section \"a # b\"]\n\tkey = v # comment\n";
        let entries = parse_config_entries(text);
        assert!(
            entries.contains(&ConfigEntry {
                section: "remote".into(),
                subsection: Some("Origin".into()),
                key: "promisor".into(),
                value: Some("true".into()),
            }),
            "quoted subsection keeps its case: {entries:?}"
        );
        // The deprecated dotted form lowercases the subsection too.
        assert!(
            entries.contains(&ConfigEntry {
                section: "remote".into(),
                subsection: Some("mirror".into()),
                key: "promisor".into(),
                value: Some("yes".into()),
            }),
            "{entries:?}"
        );
        assert!(
            entries.contains(&ConfigEntry {
                section: "extensions".into(),
                subsection: None,
                key: "partialclone".into(),
                value: Some("origin".into()),
            }),
            "{entries:?}"
        );
        // A quoted `#` inside a section subsection is not a comment.
        assert!(
            entries.contains(&ConfigEntry {
                section: "section".into(),
                subsection: Some("a # b".into()),
                key: "key".into(),
                value: Some("v".into()),
            }),
            "{entries:?}"
        );
    }

    #[test]
    fn config_entries_handle_bare_keys_and_continuations() {
        let entries =
            parse_config_entries("[remote \"x\"]\n\tpromisor\n\tfilter = blob:\\\nnone\n");
        assert!(
            entries.contains(&ConfigEntry {
                section: "remote".into(),
                subsection: Some("x".into()),
                key: "promisor".into(),
                value: None,
            }),
            "{entries:?}"
        );
        assert!(
            entries.contains(&ConfigEntry {
                section: "remote".into(),
                subsection: Some("x".into()),
                key: "filter".into(),
                value: Some("blob:none".into()),
            }),
            "{entries:?}"
        );
    }

    /// `census_git_config` over `text`, with a scratch path for any
    /// `include.path` it would follow.
    fn config_findings(text: &str) -> Vec<UnsupportedRepositoryFeature> {
        let tmp = tempfile::tempdir().expect("a scratch dir");
        let mut findings = Vec::new();
        census_git_config(
            text.as_bytes(),
            &tmp.path().join("config"),
            tmp.path(),
            &mut findings,
        );
        findings
    }

    /// A quoted config value means what it QUOTES — `"crlf"` is `crlf`, and the
    /// conversion refusal must not depend on whether the author quoted it.
    /// (An `unquote_config_value` that kept the quotes would compare `"crlf"`
    /// against `crlf` and let a checkout-converting repo census clean.)
    #[test]
    fn a_quoted_config_value_is_compared_unquoted() {
        let findings = config_findings("[core]\n\teol = \"crlf\"\n");
        assert_eq!(
            findings,
            vec![UnsupportedRepositoryFeature::GitCheckoutConversionConfig {
                key: "core.eol".to_string(),
            }],
            "a quoted crlf is the same refusal an unquoted one earns"
        );
        // And the unquote is real, not a comparison trick: the entry's stored
        // value has no quote characters.
        let entries =
            parse_config_entries("[remote \"o\"]\n\tpartialclonefilter = \"blob:none\"\n");
        assert!(
            entries.contains(&ConfigEntry {
                section: "remote".into(),
                subsection: Some("o".into()),
                key: "partialclonefilter".into(),
                value: Some("blob:none".into()),
            }),
            "a quoted value lands without its quotes: {entries:?}"
        );
    }

    /// git's key alphabet is `[a-z0-9-]` — an `_` or an empty name is not a
    /// key at all (the line is ignored, not an entry), and `-` inside a key
    /// parses fine.
    #[test]
    fn config_entry_keys_are_gits_alphabet() {
        let entries =
            parse_config_entries("[core]\n\tok-key = 1\n\tbad_key = 2\n\t = 3\n\tautocrlf = yes\n");
        assert_eq!(
            entries,
            vec![
                ConfigEntry {
                    section: "core".into(),
                    subsection: None,
                    key: "ok-key".into(),
                    value: Some("1".into()),
                },
                ConfigEntry {
                    section: "core".into(),
                    subsection: None,
                    key: "autocrlf".into(),
                    value: Some("yes".into()),
                },
            ],
            "bad_key is not a key, `= 3` has no key, `ok-key` keeps its dash"
        );
    }

    /// `core.attributesFile` refuses only when it points at something — a bare
    /// or empty value reads zero attribute declarations.
    #[test]
    fn an_empty_or_bare_attributesfile_declares_nothing() {
        assert_eq!(
            config_findings("[core]\n\tattributesFile =\n"),
            Vec::new(),
            "an empty attributesFile points at nothing"
        );
        assert_eq!(
            config_findings("[core]\n\tattributesFile\n"),
            Vec::new(),
            "a bare attributesFile points at nothing"
        );
        assert_eq!(
            config_findings("[core]\n\tattributesFile = attrs\n"),
            vec![UnsupportedRepositoryFeature::GitAttributesConfig {
                key: "core.attributesFile".to_string(),
            }],
            "a non-empty one still refuses"
        );
    }

    /// `include.path` chains are followed only to
    /// [`MAX_CONFIG_INCLUDE_DEPTH`] — the file at exactly the depth still
    /// reads, the one past it does not. One cell kills the fence's `&&`/`==`/`>=`
    /// mutants: under any of them a refused key lands where the depth says it
    /// must not (or is dropped where it must).
    #[test]
    fn include_chains_stop_at_the_depth_bound() {
        let tmp = tempfile::tempdir().expect("a scratch dir");
        // chain: config -> inc1 -> ... -> inc{MAX+1}; refused key in inc{MAX}.
        for depth in 0..=MAX_CONFIG_INCLUDE_DEPTH {
            let name = if depth == 0 {
                "config".to_string()
            } else {
                format!("inc{depth}")
            };
            let next = format!("inc{}", depth + 1);
            let mut text = format!("[include]\n\tpath = {next}\n");
            if depth == MAX_CONFIG_INCLUDE_DEPTH - 1 {
                text.push_str("[remote \"o\"]\n\tpartialCloneFilter = blob:none\n");
            }
            std::fs::write(tmp.path().join(&name), text).unwrap();
        }
        std::fs::write(
            tmp.path()
                .join(format!("inc{}", MAX_CONFIG_INCLUDE_DEPTH + 1)),
            "",
        )
        .unwrap();
        let mut findings = Vec::new();
        census_git_config(
            std::fs::read(tmp.path().join("config")).unwrap().as_slice(),
            &tmp.path().join("config"),
            tmp.path(),
            &mut findings,
        );
        assert_eq!(
            findings,
            vec![UnsupportedRepositoryFeature::PartialClone {
                key: "remote.o.partialclonefilter".to_string(),
            }],
            "the marker at exactly the include depth still lands"
        );
    }

    /// The marker one file PAST the depth bound is not read — the census
    /// cannot follow includes forever, and it says so by stopping.
    #[test]
    fn include_chains_do_not_reach_past_the_depth_bound() {
        let tmp = tempfile::tempdir().expect("a scratch dir");
        for depth in 0..=MAX_CONFIG_INCLUDE_DEPTH + 1 {
            let name = if depth == 0 {
                "config".to_string()
            } else {
                format!("inc{depth}")
            };
            let next = format!("inc{}", depth + 1);
            let mut text = format!("[include]\n\tpath = {next}\n");
            if depth == MAX_CONFIG_INCLUDE_DEPTH {
                text.push_str("[remote \"o\"]\n\tpartialCloneFilter = blob:none\n");
            }
            std::fs::write(tmp.path().join(&name), text).unwrap();
        }
        std::fs::write(
            tmp.path()
                .join(format!("inc{}", MAX_CONFIG_INCLUDE_DEPTH + 2)),
            "",
        )
        .unwrap();
        let mut findings = Vec::new();
        census_git_config(
            std::fs::read(tmp.path().join("config")).unwrap().as_slice(),
            &tmp.path().join("config"),
            tmp.path(),
            &mut findings,
        );
        assert_eq!(
            findings,
            Vec::new(),
            "the marker past the include depth is never read"
        );
    }

    /// A backslash escapes the next character in a logical line: `\#` and
    /// `\;` are literal characters, not comment markers, and a value's own
    /// `\` escapes (`\t`, `\n`) decode at unquote time.
    #[test]
    fn an_escaped_comment_marker_and_escaped_value_chars_are_literal() {
        let entries = parse_config_entries("[remote \"o\"]\n\turl = path\\#frag\n\tname = a\\tb\n");
        assert!(
            entries.contains(&ConfigEntry {
                section: "remote".into(),
                subsection: Some("o".into()),
                key: "url".into(),
                value: Some("path#frag".into()),
            }),
            "an escaped # is not a comment marker: {entries:?}"
        );
        assert!(
            entries.contains(&ConfigEntry {
                section: "remote".into(),
                subsection: Some("o".into()),
                key: "name".into(),
                value: Some("a\tb".into()),
            }),
            "a \\t escape decodes to a tab: {entries:?}"
        );
    }

    /// The logical-line reader must hand the LAST line over even when the file
    /// ends without a trailing newline — a marker on an unterminated tail line
    /// is a finding all the same.
    #[test]
    fn a_config_ending_without_a_newline_still_yields_its_last_entry() {
        // No trailing newline: `partialclone = origin` IS the tail.
        let findings = config_findings("[extensions]\n\tpartialClone = origin");
        assert_eq!(
            findings,
            vec![UnsupportedRepositoryFeature::PartialClone {
                key: "extensions.partialclone".to_string(),
            }],
            "the unterminated tail line is still an entry"
        );
        // And a DANGLING continuation — the file's last byte is `\` — leaves
        // a logical line in `pending` at EOF; it still counts.
        let entries = parse_config_entries("[remote \"o\"]\n\tfilter = blob:\\");
        assert!(
            entries.contains(&ConfigEntry {
                section: "remote".into(),
                subsection: Some("o".into()),
                key: "filter".into(),
                value: Some("blob:".into()),
            }),
            "a file ending mid-continuation still yields the pending line: {entries:?}"
        );
    }

    /// A `config` that cannot be read is not an absent one — the store census
    /// must refuse it, not silently skip the file. (The repo is LOADED first:
    /// `git`/`gix` and the census both read `config`, so the arm is only
    /// reachable once the repo is in hand.)
    #[test]
    fn an_unreadable_config_is_a_typed_refusal_not_a_clean_census() {
        let tmp = tempfile::tempdir().unwrap();
        kata_test_utils::git::init_git_repo_at(tmp.path());
        let backend = crate::JjBackend::open(tmp.path()).unwrap();
        let settings = jj_lib::settings::UserSettings::from_config(
            jj_lib::config::StackedConfig::with_defaults(),
        )
        .unwrap();
        let workspace = jj_lib::workspace::Workspace::load(
            &settings,
            backend.repo_root(),
            &jj_lib::repo::StoreFactories::default(),
            &jj_lib::workspace::default_working_copy_factories(),
        )
        .unwrap();
        let repo = futures::executor::block_on(workspace.repo_loader().load_at_head()).unwrap();

        // A directory where `config` sits: exists, but `fs::read` answers
        // EISDIR — the `Err(err)` arm, not the `NotFound` skip.
        let git_dir = tmp.path().join(".git");
        let config = git_dir.join("config");
        let moved = git_dir.join("config-moved");
        std::fs::rename(&config, &moved).unwrap();
        std::fs::create_dir(&config).unwrap();
        let mut findings = Vec::new();
        let mut sources = Vec::new();
        let verdict = census_git_store(&repo, &mut findings, &mut sources);
        std::fs::remove_dir(&config).unwrap();
        std::fs::rename(&moved, &config).unwrap();
        let err = verdict.expect_err("a config that cannot be read is a refusal");
        assert!(
            err.to_string().contains("could not read"),
            "the refusal names the unreadable file: {err}"
        );
    }

    /// An `info/attributes` that exists but cannot be read is a refusal, the
    /// same door `config` walks: a `* filter=lfs` there would still apply at
    /// git's checkout while the census saw nothing. (A symlink loop forces the
    /// non-`NotFound` read error without permissions games.)
    #[test]
    fn an_unreadable_info_attributes_is_a_typed_refusal_not_a_clean_census() {
        let tmp = tempfile::tempdir().unwrap();
        kata_test_utils::git::init_git_repo_at(tmp.path());
        let backend = crate::JjBackend::open(tmp.path()).unwrap();
        let settings = jj_lib::settings::UserSettings::from_config(
            jj_lib::config::StackedConfig::with_defaults(),
        )
        .unwrap();
        let workspace = jj_lib::workspace::Workspace::load(
            &settings,
            backend.repo_root(),
            &jj_lib::repo::StoreFactories::default(),
            &jj_lib::workspace::default_working_copy_factories(),
        )
        .unwrap();
        let repo = futures::executor::block_on(workspace.repo_loader().load_at_head()).unwrap();

        let attributes = tmp.path().join(".git").join("info").join("attributes");
        std::os::unix::fs::symlink(&attributes, &attributes).unwrap();
        let mut findings = Vec::new();
        let mut sources = Vec::new();
        let verdict = census_git_store(&repo, &mut findings, &mut sources);
        std::fs::remove_file(&attributes).unwrap();
        assert!(
            verdict.is_err(),
            "a present-but-unreadable info/attributes refuses"
        );
    }

    /// Load a `git`-fixture repo through jj and hand the loaded repo to a
    /// caller — the object `census_git_store` reads.
    fn loaded_repo(dir: &Path) -> std::sync::Arc<jj_lib::repo::ReadonlyRepo> {
        let backend = crate::JjBackend::open(dir).unwrap();
        let settings = jj_lib::settings::UserSettings::from_config(
            jj_lib::config::StackedConfig::with_defaults(),
        )
        .unwrap();
        let workspace = jj_lib::workspace::Workspace::load(
            &settings,
            backend.repo_root(),
            &jj_lib::repo::StoreFactories::default(),
            &jj_lib::workspace::default_working_copy_factories(),
        )
        .unwrap();
        futures::executor::block_on(workspace.repo_loader().load_at_head()).unwrap()
    }

    /// An `info/attributes` that is a DIRECTORY is not a declaration source:
    /// git cannot read a directory as a file either, so the census applies
    /// nothing rather than refuse. (Pins the `is_dir` arm — without it the
    /// read answers EISDIR and the file fails closed on a file it never
    /// declared.)
    #[test]
    fn a_directory_at_info_attributes_is_not_an_attribute_source() {
        let tmp = tempfile::tempdir().unwrap();
        kata_test_utils::git::init_git_repo_at(tmp.path());
        let repo = loaded_repo(tmp.path());
        std::fs::create_dir(tmp.path().join(".git/info/attributes")).unwrap();
        let mut findings = Vec::new();
        let mut sources = Vec::new();
        census_git_store(&repo, &mut findings, &mut sources)
            .expect("a directory at info/attributes is no file to read");
        assert!(
            sources
                .iter()
                .all(|(name, _)| name != "$GIT_DIR/info/attributes"),
            "a directory contributes no declarations: {sources:?}"
        );
    }

    /// A DANGLING `info/attributes` symlink is an absent file — git's own read
    /// answers ENOENT and applies nothing, so the census does the same; it is
    /// not a refusal and not a source.
    #[test]
    fn a_dangling_info_attributes_symlink_is_an_absent_file() {
        let tmp = tempfile::tempdir().unwrap();
        kata_test_utils::git::init_git_repo_at(tmp.path());
        let repo = loaded_repo(tmp.path());
        let attributes = tmp.path().join(".git/info/attributes");
        std::os::unix::fs::symlink("gone", &attributes).unwrap();
        let mut findings = Vec::new();
        let mut sources = Vec::new();
        census_git_store(&repo, &mut findings, &mut sources)
            .expect("a dangling symlink is absent, never a refusal");
        assert!(
            sources
                .iter()
                .all(|(name, _)| name != "$GIT_DIR/info/attributes"),
            "a dangling symlink contributes no declarations: {sources:?}"
        );
    }

    /// An `info/attributes` that cannot even be STAT'd is a refusal — the
    /// `NotFound` arm is absence only, not any stat failure. (`info` as a
    /// file makes the attributes stat answer ENOTDIR without permissions
    /// games.)
    #[test]
    fn an_unstatable_info_attributes_is_a_typed_refusal() {
        let tmp = tempfile::tempdir().unwrap();
        kata_test_utils::git::init_git_repo_at(tmp.path());
        let repo = loaded_repo(tmp.path());
        let info = tmp.path().join(".git/info");
        std::fs::remove_dir_all(&info).unwrap();
        std::fs::write(&info, b"not a directory").unwrap();
        let mut findings = Vec::new();
        let mut sources = Vec::new();
        let verdict = census_git_store(&repo, &mut findings, &mut sources);
        std::fs::remove_file(&info).unwrap();
        std::fs::create_dir(&info).unwrap();
        let err = verdict.expect_err("an unstatable info/attributes refuses");
        assert!(
            err.to_string().contains("could not stat"),
            "the refusal names the stat fault: {err}"
        );
    }

    /// `include.path` follows git's resolution only inside `$GIT_DIR`: a
    /// contained include's conversion key lands in the findings; `~/`,
    /// absolute, and `..`-escaping paths are `GitConfigInclude` findings rather
    /// than reads (the census never answers for a global file), and a missing
    /// include is git's silent no-op.
    #[test]
    fn include_path_follows_only_repo_contained_files() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        // A contained include — the conversion key inside it IS read.
        std::fs::write(dir.join("inc"), "[core]\n\tautocrlf = true\n").unwrap();
        let mut findings = Vec::new();
        census_git_config(
            b"[include]\n\tpath = inc\n",
            &dir.join("config"),
            dir,
            &mut findings,
        );
        assert!(
            findings.contains(&UnsupportedRepositoryFeature::GitCheckoutConversionConfig {
                key: "core.autocrlf".to_string(),
            }),
            "the contained include is still read: {findings:?}"
        );

        // Everything outside `$GIT_DIR` is a finding, not a read.
        for include in ["~/x", "/etc/kata.conf", "../escape"] {
            let mut findings = Vec::new();
            census_git_config(
                format!("[include]\n\tpath = {include}\n").as_bytes(),
                &dir.join("config"),
                dir,
                &mut findings,
            );
            assert!(
                findings
                    .iter()
                    .any(|f| matches!(f, UnsupportedRepositoryFeature::GitConfigInclude { path } if path.contains(include))),
                "{include}: {findings:?}"
            );
        }

        // A MISSING include is git's no-op — no finding, no read.
        let mut findings = Vec::new();
        census_git_config(
            b"[include]\n\tpath = absent\n",
            &dir.join("config"),
            dir,
            &mut findings,
        );
        assert!(
            findings.is_empty(),
            "a missing include contributes nothing: {findings:?}"
        );

        // A contained-but-unreadable include (a symlink loop) is a finding —
        // fail closed, never a silent pass.
        std::os::unix::fs::symlink(dir.join("loop"), dir.join("loop")).unwrap();
        let mut findings = Vec::new();
        census_git_config(
            b"[include]\n\tpath = loop\n",
            &dir.join("config"),
            dir,
            &mut findings,
        );
        assert!(
            findings
                .iter()
                .any(|f| matches!(f, UnsupportedRepositoryFeature::GitConfigInclude { .. })),
            "an unreadable include is a finding: {findings:?}"
        );
    }

    /// `..` that never climbs above `$GIT_DIR` still resolves — git honors the
    /// path as written — so `sub/../inc` reads `inc`'s conversion key rather
    /// than report an unreachable include.
    #[test]
    fn an_include_climbing_inside_the_git_dir_is_still_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        std::fs::create_dir(dir.join("sub")).unwrap();
        std::fs::write(dir.join("inc"), "[core]\n\tautocrlf = true\n").unwrap();
        let mut findings = Vec::new();
        census_git_config(
            b"[include]\n\tpath = sub/../inc\n",
            &dir.join("config"),
            dir,
            &mut findings,
        );
        assert!(
            findings.contains(&UnsupportedRepositoryFeature::GitCheckoutConversionConfig {
                key: "core.autocrlf".to_string(),
            }),
            "the contained `..` include is followed: {findings:?}"
        );
        assert!(
            !findings
                .iter()
                .any(|f| matches!(f, UnsupportedRepositoryFeature::GitConfigInclude { .. })),
            "a contained `..` is no out-of-repository include: {findings:?}"
        );
    }

    /// `autocrlf` is a refusal only when it is git's TRUE — `false`, `input`,
    /// and a value git cannot evaluate all leave committed bytes alone, so
    /// the census does not refuse them.
    #[test]
    fn a_non_true_autocrlf_is_no_conversion() {
        for value in ["autocrlf = false", "autocrlf = input", "autocrlf = banana"] {
            let findings = config_findings(&format!("[core]\n\t{value}\n"));
            assert!(
                findings.is_empty(),
                "`{value}` is no checkout conversion: {findings:?}"
            );
        }
        // The bare form is git's true and still refuses.
        let findings = config_findings("[core]\n\tautocrlf\n");
        assert!(
            findings.contains(&UnsupportedRepositoryFeature::GitCheckoutConversionConfig {
                key: "core.autocrlf".to_string(),
            }),
            "a bare autocrlf is git's true: {findings:?}"
        );
    }

    /// A promisor remote declares the clone partial — bare and `true` alike
    /// — while git's own `promisor = false` is the off switch the census
    /// must not refuse.
    #[test]
    fn a_promisor_remote_is_a_partial_clone_finding() {
        for text in [
            "[remote \"x\"]\n\tpromisor\n",
            "[remote \"x\"]\n\tpromisor = true\n",
        ] {
            assert_eq!(
                config_findings(text),
                vec![UnsupportedRepositoryFeature::PartialClone {
                    key: "remote.x.promisor".to_string(),
                }],
                "{text:?}"
            );
        }
        assert!(
            config_findings("[remote \"x\"]\n\tpromisor = false\n").is_empty(),
            "an explicit promisor = false is git's off"
        );
    }

    #[test]
    fn promisor_values_mean_what_git_means() {
        assert_eq!(config_value_is_true(None), Some(true));
        assert_eq!(config_value_is_true(Some("true")), Some(true));
        assert_eq!(config_value_is_true(Some("1")), Some(true));
        assert_eq!(config_value_is_true(Some("false")), Some(false));
        assert_eq!(config_value_is_true(Some("0")), Some(false));
        assert_eq!(config_value_is_true(Some("")), Some(false));
        assert_eq!(config_value_is_true(Some("banana")), None);
    }
}
