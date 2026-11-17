//! Workflow standard library — layered name-based resolution.
//!
//! A `WorkflowLibrary` resolves a workflow *name* (e.g. `self-review`) to a
//! file path by searching a list of **roots** in priority order:
//!
//! 1. **Project roots** — e.g. `./.kata/workflows/` next to the user's
//!    checkout. Highest priority; allow a repo to shadow a stdlib entry.
//! 2. **User roots** — e.g. `~/.kata/workflows/`. User-level overrides
//!    that apply across all projects.
//! 3. **Bundled roots** — the built-in library shipped with kata. Lowest
//!    priority so users can always override.
//!
//! Inside a single root, a name matches the first file whose stem equals
//! the name and whose extension is `.star`. Starlark is the sole workflow
//! frontend — a `.toml` file is not a workflow definition.
//!
//! ## Security: FileLoader whitelist
//!
//! Starlark's `load("<path>", "<sym>")` statement is powerful but
//! dangerous: a naive loader would let workflows read arbitrary files
//! off the host. This module also provides the crate-private
//! `WhitelistedFileLoader`, a `starlark::eval::FileLoader` that resolves
//! `load()` paths against a fixed list of canonicalized roots and **rejects
//! anything that escapes those roots** after canonicalization. Symlinks are
//! canonicalized so a symlink pointing outside the whitelist still
//! fails. `..` components in the requested path that climb out of the
//! root are rejected for the same reason. Every module it loads evaluates
//! under the importing evaluation's statement budget, wall-clock backstop and
//! cancel flag.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use kata_types::ContentHash;
use kata_types::workflow::{WorkflowSourceFormat, workflow_import_hash};
use kata_types::{KataError, KataResult};

/// Re-exported so callers reading pack-discovery metadata via
/// [`WorkflowLibrary::read_pack_metadata`] don't need to know it actually
/// lives in `crate::parser` (a private module).
pub use crate::parser::PackMetadata;
use starlark::environment::{FrozenModule, Globals, Module};
use starlark::eval::{Evaluator, FileLoader};
use starlark::syntax::{AstModule, Dialect};

use crate::starlark_eval::StarlarkEvalBudget;

fn discover_checkout_root(current_exe: Option<&Path>) -> Option<PathBuf> {
    current_exe
        .into_iter()
        .flat_map(Path::ancestors)
        .find(|ancestor| {
            ancestor.join("Cargo.toml").is_file() && ancestor.join("workflows/std").is_dir()
        })
        .map(Path::to_path_buf)
}

/// One entry in a `WorkflowLibrary` listing. Each entry corresponds to
/// exactly one file on disk. Multiple roots may produce entries with
/// the same name, in which case the higher-priority root shadows the
/// lower one during resolution; `list()` still reports the shadowed
/// entries so operators can see the full picture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowEntry {
    /// Canonical workflow name (file stem).
    pub name: String,
    /// Absolute path to the file on disk.
    pub path: PathBuf,
    /// Root directory this entry was discovered in (one of the
    /// `WorkflowLibrary` roots).
    pub root: PathBuf,
    /// Priority of the root (lower = higher priority: 0 = project,
    /// 1 = user, 2 = bundled). Used by `list()` to sort and flag
    /// shadowed entries.
    pub root_priority: usize,
}

impl WorkflowEntry {
    /// Every library entry is a `.star` file (`list`, `lookup_in_root`), so its
    /// source format is a property of the type, not of a row.
    pub const FORMAT: WorkflowSourceFormat = WorkflowSourceFormat::Starlark;
}

/// A searchable workflow standard library backed by a list of roots.
#[derive(Debug, Clone)]
pub struct WorkflowLibrary {
    roots: Vec<PathBuf>,
}

impl WorkflowLibrary {
    /// Build a library over the given roots, in priority order.
    /// Nonexistent roots are kept in the list (they're simply empty)
    /// so adding a directory after the library is constructed does not
    /// require rebuilding it — the filesystem is re-read on every call.
    #[must_use]
    pub fn new(roots: Vec<PathBuf>) -> Self {
        Self { roots }
    }

    /// Build a library using the conventional roots:
    ///
    /// 1. `<cwd>/.kata/workflows` (project)
    /// 2. `$HOME/.kata/workflows` (user)
    /// 3. `$KATA_STDLIB_DIR` (+ its siblings `kata-factory`, `examples` and
    ///    `smoke`), else
    ///    `<exe dir>/../share/kata/{workflows,kata-factory,examples}`. A
    ///    runtime-discovered checkout is used only when no installed directory
    ///    exists and the executable lives under that checkout's `target/`
    ///    directory. This keeps development binaries convenient without leaking
    ///    build-host paths into an installed or copied product binary.
    ///
    /// The bundled tier ships THREE sibling roots at the SAME priority: the
    /// generic DSL-core stdlib (`workflows/std`, holding `kata/std.star`), the
    /// kata-factory product builders (`workflows/kata-factory`, holding
    /// `kata/factory.star`), and the curated example pack
    /// (`workflows/examples`, installed as `share/kata/examples`). All three are
    /// searched for every `load()` path, so a std pack's
    /// `load("kata/factory.star", ..)` and a factory lib's
    /// `load("kata/std.star", ..)` both resolve cross-root.
    ///
    /// The example pack is appended LAST within the bundled tier, so it has the
    /// lowest priority of every root and can therefore never shadow a project,
    /// user, std, or kata-factory workflow of the same name. That ordering is
    /// what makes the learning surface resolvable by name
    /// (`kata run hello-workflow`) without it being able to change what any
    /// already-resolving name executes.
    ///
    /// The gate's smoke rigs (`workflows/smoke`) are NOT part of the bundle: no
    /// installed layout carries them and the checkout fallback does not name them,
    /// so neither an installed nor a source-installed `kata` lists or resolves
    /// them. Only an explicit `$KATA_STDLIB_DIR` reaches them, through its `smoke`
    /// sibling, appended after `examples` so a rig can never shadow a shipped
    /// workflow — the door the test harnesses and smoke recipes open by naming the
    /// checkout's `workflows/std`.
    ///
    /// Missing directories are allowed and simply contribute no entries.
    ///
    /// If NONE of the resolved roots exist on disk the library degrades
    /// **loudly** — it emits a `tracing::warn!` naming every tried path
    /// (see [`no_roots_present_warning`]) rather than silently resolving
    /// zero workflows. A fresh-box install that finds no stdlib is an
    /// operator error worth a log line, not a silent empty library.
    #[must_use]
    pub fn default_roots() -> Self {
        let cwd = std::env::current_dir().ok();
        let home = std::env::var("HOME").ok();
        let stdlib_dir = std::env::var("KATA_STDLIB_DIR").ok();
        let current_exe = std::env::current_exe().ok();
        let checkout_root = discover_checkout_root(current_exe.as_deref());
        let manifest_dir = checkout_root.map(|root| root.join("crates/program"));
        let roots = resolve_default_roots(
            cwd.as_deref(),
            home.as_deref(),
            stdlib_dir.as_deref(),
            current_exe.as_deref(),
            manifest_dir
                .as_deref()
                .and_then(Path::to_str)
                .unwrap_or_default(),
        );
        if let Some(warning) = no_roots_present_warning(&roots) {
            tracing::warn!("{warning}");
        }
        if let Some(warning) =
            incomplete_installed_layout_warning(current_exe.as_deref(), stdlib_dir.as_deref())
        {
            tracing::warn!("{warning}");
        }
        Self::new(roots)
    }

    /// The configured roots, in priority order (highest priority first).
    #[must_use]
    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// Resolve `name` to a single file path. The first matching root
    /// wins; within a root, the sole recognized format is `.star` (see
    /// [`lookup_in_root`]).
    /// Returns `KataError::Validation` if no root contains a match.
    pub fn resolve(&self, name: &str) -> KataResult<PathBuf> {
        if !is_valid_name(name) {
            return Err(KataError::Validation(format!(
                "invalid workflow name {name:?}: names must be non-empty and \
                 contain only ASCII letters, digits, '-', '_', or '.'"
            )));
        }

        for root in &self.roots {
            if let Some(path) = lookup_in_root(root, name) {
                return Ok(path);
            }
        }
        Err(KataError::Validation(format!(
            "workflow {name:?} not found in any library root. \
             Searched: {:?}",
            self.roots
        )))
    }

    /// Enumerate every workflow entry across every root, sorted by
    /// name then by root priority. Shadowed entries (a higher-priority
    /// root and a lower-priority root both have the same name) are
    /// all included — callers that want the effective set should
    /// dedupe by name and keep the lowest `root_priority`.
    #[must_use]
    pub fn list(&self) -> Vec<WorkflowEntry> {
        let mut entries: Vec<WorkflowEntry> = Vec::new();
        for (priority, root) in self.roots.iter().enumerate() {
            let Ok(read_dir) = std::fs::read_dir(root) else {
                continue;
            };
            let mut per_root: BTreeMap<String, WorkflowEntry> = BTreeMap::new();
            for dirent in read_dir.flatten() {
                let path = dirent.path();
                if !path.is_file() {
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("star") {
                    continue;
                }
                let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                    continue;
                };
                if !is_valid_name(stem) {
                    continue;
                }
                let entry = WorkflowEntry {
                    name: stem.to_owned(),
                    path: path.clone(),
                    root: root.clone(),
                    root_priority: priority,
                };
                per_root.insert(stem.to_owned(), entry);
            }
            entries.extend(per_root.into_values());
        }
        entries.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then(a.root_priority.cmp(&b.root_priority))
        });
        entries
    }

    /// Return the effective entries — one per name, highest priority wins.
    /// This is what `kata workflows list` should show by default; pass
    /// `--all` to see the raw output of `list()` with shadowed rows.
    #[must_use]
    pub fn list_effective(&self) -> Vec<WorkflowEntry> {
        let mut seen: std::collections::BTreeMap<String, WorkflowEntry> =
            std::collections::BTreeMap::new();
        for entry in self.list() {
            seen.entry(entry.name.clone())
                .and_modify(|existing| {
                    if entry.root_priority < existing.root_priority {
                        *existing = entry.clone();
                    }
                })
                .or_insert(entry);
        }
        seen.into_values().collect()
    }

    /// Read a pack's discovery metadata (`description` /
    /// `version` / `tags` / `params`) by evaluating it through the same
    /// checked Starlark path `resolve()` + inspection use
    /// ([`crate::parser::from_file_with_library_checked`]), so the reported
    /// metadata always matches what the pack actually compiles to.
    ///
    /// Errors (parse/compile failure) propagate as-is — callers that want a
    /// best-effort listing (e.g. `kata workflows list`) should treat a
    /// failure here as "metadata unavailable" rather than aborting the whole
    /// listing.
    pub fn read_pack_metadata(&self, entry: &WorkflowEntry) -> KataResult<PackMetadata> {
        let checked = crate::parser::from_file_with_library_checked(&entry.path, self.roots())?;
        Ok(checked.pack_metadata().clone())
    }
}

/// Pure resolution of the conventional workflow-library roots from injected
/// inputs. Split out of [`WorkflowLibrary::default_roots`] so the
/// installed-layout resolution (relative to the executable) is testable
/// without mutating process-global `current_exe`/env — pass a fake exe path
/// under a tempdir and assert the
/// `../share/kata/{workflows,kata-factory,examples}` roots materialize. The
/// bundle is a TRIPLE: `examples` joined it as the LOWEST-priority root, which
/// is what makes `kata run hello-workflow` resolve from an installed artifact
/// without letting an example shadow anything.
///
/// Inputs mirror the real environment sources:
/// * `cwd` — `std::env::current_dir()` (project root `./.kata/workflows`)
/// * `home` — `$HOME` (user root `~/.kata/workflows`)
/// * `stdlib_dir` — `$KATA_STDLIB_DIR` (explicit override; its `kata-factory`,
///   `examples` and `smoke` siblings are added too, `smoke` last)
/// * `current_exe` — `std::env::current_exe()` (installed layout
///   `<exe>/../share/kata/{workflows,kata-factory,examples}`)
/// * `manifest_dir` — runtime-discovered checkout hint (dev fallback
///   `<repo>/workflows/{std,kata-factory,examples}`), never a build-host path
///   baked into the production binary
///
/// When `KATA_STDLIB_DIR` is unset, the installed layout is authoritative if
/// any bundled directory exists. The runtime checkout fallback is
/// appended only when all installed directories are absent *and* the
/// executable is under the discovered checkout's `target/` directory. This
/// keeps a Cargo development binary convenient while ensuring a relocated or
/// copied package neither advertises nor depends on its build host's source
/// tree.
#[must_use]
pub fn resolve_default_roots(
    cwd: Option<&Path>,
    home: Option<&str>,
    stdlib_dir: Option<&str>,
    current_exe: Option<&Path>,
    manifest_dir: &str,
) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();

    // Project root: ./.kata/workflows
    if let Some(cwd) = cwd {
        roots.push(cwd.join(".kata").join("workflows"));
    }

    // User root: $HOME/.kata/workflows
    if let Some(home) = home
        && !home.is_empty()
    {
        roots.push(PathBuf::from(home).join(".kata").join("workflows"));
    }

    // Bundled roots. THREE sibling bundled roots ship at the SAME priority
    // tier: the generic DSL-core stdlib, the kata-factory product builders,
    // and the curated example pack. The kata-factory root is appended right
    // after the std root in every mode so both the whitelisted loader and
    // pack discovery see them, and cross-root `load()` (a std pack loading
    // `kata/factory.star`, a factory lib loading `kata/std.star`) resolves.
    // The example pack is appended LAST in every mode: it is a learning
    // surface, so it must be resolvable by name (`kata run hello-workflow`)
    // but must never shadow a project, user, std, or factory workflow that
    // happens to share a stem.
    // An empty `KATA_STDLIB_DIR` is treated as unset (mirrors the `$HOME`
    // handling above): an operator who exports `KATA_STDLIB_DIR=` should get
    // the installed-layout resolution, not a bogus `""` root that shadows it.
    if let Some(explicit) = stdlib_dir.filter(|s| !s.is_empty()) {
        let explicit = PathBuf::from(explicit);
        // The kata-factory and examples roots are the `kata-factory` and
        // `examples` siblings of the explicit stdlib dir (mirrors the
        // installed `share/kata/{workflows,kata-factory,examples}` and dev
        // `workflows/{std,kata-factory,examples}` sibling layouts). The
        // `smoke` sibling of ANY explicit dir is a root too, LAST so it never
        // shadows a shipped name: a checkout's `workflows/smoke` holds the gate
        // rigs, and no packaged layout has a `smoke` sibling, so an explicit
        // dir naming an install adds a root that does not exist. If the
        // explicit path has no parent, fall back to just the explicit root.
        if let Some(parent) = explicit.parent() {
            let factory = parent.join("kata-factory");
            let examples = parent.join("examples");
            let smoke = parent.join("smoke");
            roots.push(explicit);
            roots.push(factory);
            roots.push(examples);
            roots.push(smoke);
        } else {
            roots.push(explicit);
        }
    } else {
        // Installed layout:
        // <exe>/../share/kata/{workflows,kata-factory,examples}.
        // `just package` materializes exactly this layout
        // (dist/bin/kata + dist/share/kata/{workflows,kata-factory,examples});
        // the `<exe>/..` walk lands on the dist root regardless of where the
        // tree is copied.
        let installed = current_exe
            .and_then(Path::parent)
            .and_then(Path::parent)
            .map(|parent| {
                let base = parent.join("share").join("kata");
                vec![
                    base.join("workflows"),
                    base.join("kata-factory"),
                    base.join("examples"),
                ]
            })
            .unwrap_or_default();
        let installed_present = installed.iter().any(|root| root.is_dir());
        roots.extend(installed);

        let repo_root = PathBuf::from(manifest_dir)
            .parent()
            .and_then(Path::parent)
            .map(Path::to_path_buf);
        let development_executable = repo_root.as_ref().is_some_and(|repo| {
            current_exe.is_some_and(|exe| exe.starts_with(repo.join("target")))
        });
        if !installed_present && development_executable {
            // Development fallback:
            // `<repo>/workflows/{std,kata-factory,examples}`, relative to the
            // runtime-discovered program-crate manifest. It is never appended
            // for an executable copied outside this checkout's Cargo target
            // tree or when an installed root exists.
            if let Some(repo) = repo_root {
                roots.push(repo.join("workflows").join("std"));
                roots.push(repo.join("workflows").join("kata-factory"));
                roots.push(repo.join("workflows").join("examples"));
            }
        }
    }

    roots
}

/// Diagnose a damaged executable-relative bundle without reaching back into a
/// a build-time checkout. An explicit `KATA_STDLIB_DIR` owns its own layout and
/// bypasses this installed-bundle check.
///
/// The bundle is a TRIPLE — `share/kata/{workflows,kata-factory,examples}` —
/// and all three are resolution roots, so a tree carrying only some of them
/// resolves strictly fewer workflows BY NAME than the artifact advertises.
/// That is exactly the silent degrade this exists to name, so the check fires
/// unless the three directories are uniformly present or uniformly absent.
#[must_use]
pub fn incomplete_installed_layout_warning(
    current_exe: Option<&Path>,
    stdlib_dir: Option<&str>,
) -> Option<String> {
    if stdlib_dir.is_some_and(|value| !value.is_empty()) {
        return None;
    }
    let base = current_exe
        .and_then(Path::parent)
        .and_then(Path::parent)?
        .join("share")
        .join("kata");
    let expected = [
        base.join("workflows"),
        base.join("kata-factory"),
        base.join("examples"),
    ];
    let present = expected.iter().filter(|dir| dir.is_dir()).count();
    if present == 0 || present == expected.len() {
        return None;
    }
    let missing = expected
        .iter()
        .filter(|dir| !dir.is_dir())
        .map(|dir| dir.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "kata workflow stdlib: INCOMPLETE installed bundle — expected all of {}, {} and {}; \
         MISSING: {missing}. The installed layout remains authoritative and Kata will not read \
         the build host's source checkout. Reinstall the complete artifact or set \
         KATA_STDLIB_DIR.",
        expected[0].display(),
        expected[1].display(),
        expected[2].display(),
    ))
}

/// Loud-degrade guard for the workflow standard library.
///
/// Returns a warning message naming every tried root when NONE of them
/// exist on disk — i.e. the library would resolve zero workflows. Returns
/// `None` the moment at least one root is a directory (the common healthy
/// case). Callers (`default_roots`) route the message through
/// `tracing::warn!` so a fresh-box install with a missing stdlib fails
/// *loudly* instead of silently returning an empty library.
#[must_use]
pub fn no_roots_present_warning(roots: &[PathBuf]) -> Option<String> {
    if roots.iter().any(|r| r.is_dir()) {
        return None;
    }
    Some(format!(
        "kata workflow stdlib: NONE of the {} candidate library roots exist on \
         disk — the library will resolve ZERO workflows. Tried: {roots:?}. Fix: \
         set KATA_STDLIB_DIR to your stdlib directory, or run `just package` to \
         materialize share/kata/{{workflows,kata-factory,examples}} next to the binary.",
        roots.len()
    ))
}

fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        // Reject names that are just dots — they'd collide with path traversal.
        && name != "."
        && name != ".."
}

fn lookup_in_root(root: &Path, name: &str) -> Option<PathBuf> {
    if !root.is_dir() {
        return None;
    }
    let candidate = root.join(format!("{name}.star"));
    if candidate.is_file() {
        return Some(candidate);
    }
    None
}

// ---------------------------------------------------------------------------
// Starlark FileLoader with path whitelist
// ---------------------------------------------------------------------------

/// A Starlark `FileLoader` that resolves `load()` paths against a
/// fixed whitelist of root directories. Any attempt to load a file
/// outside the whitelist (including via `..` traversal, absolute
/// paths, or symlinks pointing out of tree) is rejected with
/// `KataError::Validation`.
///
/// The loader shares the caller's [`Globals`] when evaluating loaded
/// modules and recursively installs itself for loaded modules too, so
/// stdlib modules can compose through nested `load()` calls while keeping
/// the same whitelist and import-hash accounting.
pub(crate) struct WhitelistedFileLoader {
    /// Canonicalized roots. Any load path must, after resolution
    /// against one of these roots, canonicalize back to a subpath
    /// of the same root.
    roots: Vec<PathBuf>,
    /// Shared globals handed to loaded modules so builtins remain
    /// consistent with the caller.
    globals: Arc<Globals>,
    /// Authored load path -> exact loaded-source hash.
    import_hashes: Arc<Mutex<BTreeMap<String, ContentHash>>>,
    /// The importing evaluation's budget, installed on every loaded module's
    /// evaluator: a `load()`ed module spends the importer's statements and
    /// observes its cancel, at any load depth.
    budget: Arc<StarlarkEvalBudget>,
}

impl WhitelistedFileLoader {
    /// Build a loader with the given root directories. Nonexistent
    /// roots are silently dropped (they cannot match anything
    /// anyway); roots that exist are canonicalized up-front so the
    /// hot path is a pure prefix check.
    #[must_use]
    pub(crate) fn new(
        roots: &[PathBuf],
        globals: Arc<Globals>,
        budget: Arc<StarlarkEvalBudget>,
    ) -> Self {
        let canonical_roots: Vec<PathBuf> = roots
            .iter()
            .filter_map(|r| std::fs::canonicalize(r).ok())
            .collect();
        Self {
            roots: canonical_roots,
            globals,
            import_hashes: Arc::new(Mutex::new(BTreeMap::new())),
            budget,
        }
    }

    /// Deterministic snapshot of all successfully resolved Starlark imports.
    #[must_use]
    pub fn import_hashes(&self) -> BTreeMap<String, ContentHash> {
        self.import_hashes
            .lock()
            .map(|hashes| hashes.clone())
            .unwrap_or_default()
    }

    /// Resolve a requested load path against the whitelist. Returns
    /// the canonicalized target file on success. Fails with a
    /// descriptive error if the path escapes every root, references
    /// a non-existent file, or names a directory.
    pub fn resolve(&self, requested: &str) -> KataResult<PathBuf> {
        if self.roots.is_empty() {
            return Err(KataError::Validation(format!(
                "load(\"{requested}\") rejected: no library roots are configured"
            )));
        }
        // Reject absolute paths outright — they sidestep the roots.
        let requested_path = Path::new(requested);
        if requested_path.is_absolute() {
            return Err(KataError::Validation(format!(
                "load(\"{requested}\") rejected: absolute paths are not allowed"
            )));
        }

        for root in &self.roots {
            let candidate = root.join(requested_path);
            let Ok(canonical) = std::fs::canonicalize(&candidate) else {
                continue;
            };
            if !canonical.starts_with(root) {
                // Symlink escape attempt. Try the next root; if none
                // accept it, we fall through to the error below.
                continue;
            }
            if !canonical.is_file() {
                return Err(KataError::Validation(format!(
                    "load(\"{requested}\") rejected: resolved target is not a file"
                )));
            }
            return Ok(canonical);
        }
        Err(KataError::Validation(format!(
            "load(\"{requested}\") rejected: target not found in any whitelisted root"
        )))
    }
}

impl FileLoader for WhitelistedFileLoader {
    fn load(&self, path: &str) -> starlark::Result<FrozenModule> {
        let resolved = self
            .resolve(path)
            .map_err(|e| starlark::Error::new_other(anyhow::anyhow!("{e}")))?;

        let source = std::fs::read_to_string(&resolved).map_err(|e| {
            starlark::Error::new_other(anyhow::anyhow!(
                "failed to read load target {}: {e}",
                resolved.display()
            ))
        })?;

        self.import_hashes
            .lock()
            .map_err(|_| {
                starlark::Error::new_other(anyhow::anyhow!(
                    "failed to record load target hash for {}: import hash lock poisoned",
                    resolved.display()
                ))
            })?
            .insert(path.to_owned(), workflow_import_hash(source.as_bytes()));

        let filename = resolved.display().to_string();
        let ast = AstModule::parse(&filename, source, &Dialect::Standard)?;

        let module = Module::new();
        {
            // Isolate this loaded module from the top-level file's workflow
            // graph: `load()`ed libs share this thread's `stage()`/`workflow()`/
            // `schedule()` builtins, so a module-scope call would otherwise
            // register into — and silently corrupt (stage/workflow) or silently
            // drop (schedule) — the importer's pack. The guard snapshots+clears
            // the builder AND the schedule registry, restoring both on drop.
            let _isolation = crate::dsl::builder::isolate_for_load();
            let mut eval = Evaluator::new(&module);
            self.budget.install(&mut eval);
            eval.set_loader(self);
            eval.eval_module(ast, &self.globals)?;
            // Reject a loaded helper that authored a graph OR declared a durable
            // schedule. `schedule()` gets the SAME loud load-time error as
            // `stage()`/`workflow()` — a schedule factored into a shared `.star`
            // and `load()`ed would otherwise arm nothing and warn nothing.
            if crate::dsl::builder::workflow_builder_touched()
                || crate::dsl::builder::schedule_registered()
            {
                return Err(starlark::Error::new_other(anyhow::anyhow!(
                    "load(\"{path}\") target called stage()/workflow()/schedule() at module scope; \
                     loaded libraries may define helpers but must not author a workflow graph \
                     or declare a durable schedule"
                )));
            }
        }
        module.freeze().map_err(starlark::Error::from)
    }
}

#[cfg(test)]
mod checkout_discovery_tests {
    use super::*;

    #[test]
    fn runtime_checkout_discovery_is_bound_to_the_executable_checkout() {
        let fixture = tempfile::tempdir().expect("fixture");
        let repo_a = fixture.path().join("repo-a");
        let repo_b = fixture.path().join("repo-b");
        for repo in [&repo_a, &repo_b] {
            std::fs::create_dir_all(repo.join("workflows/std")).expect("stdlib");
            std::fs::write(repo.join("Cargo.toml"), "[workspace]\n").expect("manifest");
        }
        let target_exe = repo_a.join("target/debug/kata");
        let external_exe = fixture.path().join("external-target/kata");
        let installed_exe = fixture.path().join("installed/bin/kata");

        // Running repo A's binary while cwd is inside repo B must still bind
        // the development fallback to repo A. Cwd is intentionally absent from
        // this discovery API; it remains only the project-workflow root.
        assert_eq!(discover_checkout_root(Some(&target_exe)), Some(repo_a));
        assert_eq!(discover_checkout_root(Some(&external_exe)), None);
        assert_eq!(discover_checkout_root(Some(&installed_exe)), None);
        assert_eq!(discover_checkout_root(None), None);
    }
}

/// The load-path whitelist, driven directly rather than through an evaluation.
#[cfg(test)]
mod loader_tests {
    use super::*;
    use tempfile::TempDir;

    fn touch(dir: &Path, relative: &str, content: &str) -> PathBuf {
        let path = dir.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, content).unwrap();
        path
    }

    fn loader_over(roots: &[PathBuf]) -> WhitelistedFileLoader {
        WhitelistedFileLoader::new(
            roots,
            Arc::new(Globals::standard()),
            StarlarkEvalBudget::unreachable_for_tests(),
        )
    }

    #[test]
    fn loader_loads_file_inside_root() {
        let root = TempDir::new().unwrap();
        touch(
            root.path(),
            "helpers.star",
            "def greet(who): return 'hello ' + who\n",
        );
        let loader = loader_over(&[root.path().into()]);
        let module = loader.load("helpers.star").expect("load should succeed");
        // The loaded FrozenModule should expose `greet`.
        assert!(module.get_option("greet").unwrap().is_some());
        assert_eq!(
            loader.import_hashes().get("helpers.star"),
            Some(&workflow_import_hash(
                b"def greet(who): return 'hello ' + who\n"
            ))
        );
    }

    #[test]
    fn loader_supports_nested_loads_inside_root() {
        let root = TempDir::new().unwrap();
        touch(root.path(), "base.star", "def noun(): return 'kata'\n");
        touch(
            root.path(),
            "helpers.star",
            "load(\"base.star\", \"noun\")\ndef greet(): return 'hello ' + noun()\n",
        );

        let loader = loader_over(&[root.path().into()]);
        let module = loader.load("helpers.star").expect("load should succeed");

        assert!(module.get_option("greet").unwrap().is_some());
        let import_hashes = loader.import_hashes();
        assert_eq!(
            import_hashes.get("helpers.star"),
            Some(&workflow_import_hash(
                b"load(\"base.star\", \"noun\")\ndef greet(): return 'hello ' + noun()\n"
            ))
        );
        assert_eq!(
            import_hashes.get("base.star"),
            Some(&workflow_import_hash(b"def noun(): return 'kata'\n"))
        );
    }

    #[test]
    fn loader_rejects_absolute_path() {
        let root = TempDir::new().unwrap();
        touch(root.path(), "ok.star", "def x(): return 1\n");
        let loader = loader_over(&[root.path().into()]);
        let err = loader.load("/etc/passwd").unwrap_err().to_string();
        assert!(
            err.contains("absolute paths are not allowed"),
            "expected absolute-path rejection, got: {err}"
        );
    }

    #[test]
    fn loader_rejects_traversal_outside_root() {
        // Create two temp dirs. The loader is whitelisted on `inside`;
        // the traversal attempts to reach a file in `outside`.
        let inside = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        touch(outside.path(), "secret.star", "def pw(): return 'oops'\n");
        let loader = loader_over(&[inside.path().into()]);

        // Relative traversal: ../<basename of outside>/secret.star
        let outside_name = outside.path().file_name().unwrap().to_string_lossy();
        let traversal = format!("../{outside_name}/secret.star");
        let err = loader.load(&traversal).unwrap_err().to_string();
        assert!(
            err.contains("target not found") || err.contains("rejected"),
            "expected traversal rejection, got: {err}"
        );
    }

    #[test]
    fn loader_rejects_symlink_escape() {
        // Symlink `link.star` inside the whitelist pointing at a file
        // outside the whitelist. Canonicalization must unmask the
        // escape and the loader must reject it.
        #[cfg(unix)]
        {
            let inside = TempDir::new().unwrap();
            let outside = TempDir::new().unwrap();
            let target = touch(outside.path(), "secret.star", "def pw(): return 'oops'\n");
            std::os::unix::fs::symlink(&target, inside.path().join("link.star")).unwrap();

            let loader = loader_over(&[inside.path().into()]);
            let err = loader.load("link.star").unwrap_err().to_string();
            assert!(
                err.contains("rejected") || err.contains("not found"),
                "expected symlink escape rejection, got: {err}"
            );
        }
    }

    #[test]
    fn loader_with_empty_roots_rejects_everything() {
        let loader = loader_over(&[]);
        let err = loader.load("anything.star").unwrap_err().to_string();
        assert!(err.contains("no library roots"), "got: {err}");
    }
}
