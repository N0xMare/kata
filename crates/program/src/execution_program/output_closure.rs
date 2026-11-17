//! The declared-vs-observed OUTPUT CLOSURE check.
//!
//! A stage's DECLARED output set
//! ([`ExecutionProgramStage::produces_files`](super::ExecutionProgramStage::produces_files),
//! authored via `stage(produces_files=[..])`) checked against its OBSERVED output
//! set (the paths the stage's accepted `/work` delta changed, recorded at
//! completion). Without a checkable
//! declared/observed output closure there is no manifest to content-address — the
//! effect model cannot CAS an output tree without knowing what a
//! stage's outputs ARE.
//!
//! Scope boundary: this builds ONLY the declared + observed + checkable
//! closure. It does NOT content-address the output tree, mint a `tree_id`, or
//! wire the CAS — the effect model consumes this manifest for that.
//!
//! The check is a PURE, backend-agnostic predicate ([`check_output_closure`]): it
//! takes the declared globs and the observed repo-relative paths and flags every
//! observed path covered by NO declared glob (observed ⊄ declared). It performs no
//! filesystem access, so it is trivially deterministic and testable.

use smol_str::SmolStr;

/// The result of checking a stage's OBSERVED output set against its DECLARED
/// output-file closure.
///
/// [`Self::undeclared`] is the set of closure VIOLATIONS — observed paths the
/// stage produced/modified that no declared glob covers. A conforming stage has
/// an empty violation set ([`Self::is_conforming`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OutputClosureReport {
    /// Observed paths matching NO declared glob — the closure violations
    /// (sorted, deduped). Empty iff the stage conforms to its declared closure.
    pub undeclared: Vec<SmolStr>,
}

impl OutputClosureReport {
    /// True iff every observed output path is covered by the declared closure —
    /// i.e. the observed output set is a subset of the declared closure.
    #[must_use]
    pub fn is_conforming(&self) -> bool {
        self.undeclared.is_empty()
    }
}

/// Check an OBSERVED output set against a DECLARED output-file closure.
///
/// PURE + backend-agnostic. Each `declared` entry is a repo-relative pattern:
///
/// * A pattern with NO glob metacharacter (`*`, `?`, `[`) is treated as either an
///   exact file path OR a DIRECTORY scope — an observed path is covered when it
///   equals the entry or lies inside it (`entry` is a path prefix ending on a `/`
///   boundary). This mirrors the `mutation_policy=owned_paths` scope semantics.
/// * A pattern WITH a glob metacharacter is matched with
///   `require_literal_separator = true`, so `*`/`?` never cross `/` and `**`
///   matches across directories — matching author intuition and the `reads=`
///   closure resolution. A trailing `dir/**` additionally covers everything under
///   `dir/` (belt-and-suspenders with glob's own `**` handling).
///
/// An observed path covered by no declared entry is UNDECLARED. When `declared` is
/// empty every observed path is undeclared — callers gate enforcement on a
/// NON-EMPTY declared closure (an empty `produces_files=` is a vacuous, unchecked
/// closure), so a stage that declares nothing is never flagged.
#[must_use]
pub fn check_output_closure<D, O>(declared: &[D], observed: &[O]) -> OutputClosureReport
where
    D: AsRef<str>,
    O: AsRef<str>,
{
    let matchers: Vec<DeclaredMatcher> = declared
        .iter()
        .filter_map(|entry| DeclaredMatcher::compile(entry.as_ref()))
        .collect();

    let mut undeclared = Vec::new();
    for obs in observed {
        let path = normalize_relative(obs.as_ref());
        if path.is_empty() {
            continue;
        }
        if !matchers.iter().any(|matcher| matcher.covers(&path)) {
            undeclared.push(SmolStr::new(&path));
        }
    }
    undeclared.sort();
    undeclared.dedup();
    OutputClosureReport { undeclared }
}

/// A compiled declared-closure entry. Either a glob pattern (optionally with a
/// directory prefix for a trailing `/**`) or a plain path/directory scope.
enum DeclaredMatcher {
    /// A literal path OR a directory scope: covers `scope` exactly and anything
    /// inside `scope/`.
    Scope { scope: String },
    /// A glob pattern. `dir_prefix` is `Some(dir)` for a trailing `dir/**`, so the
    /// whole subtree under `dir/` is covered regardless of glob `**` edge cases.
    Glob {
        pattern: glob::Pattern,
        dir_prefix: Option<String>,
    },
}

impl DeclaredMatcher {
    fn compile(entry: &str) -> Option<Self> {
        let entry = normalize_relative(entry);
        if entry.is_empty() {
            return None;
        }
        if entry.contains(['*', '?', '[']) {
            let dir_prefix = entry
                .strip_suffix("/**")
                .filter(|prefix| !prefix.is_empty() && !prefix.contains(['*', '?', '[']))
                .map(ToOwned::to_owned);
            // A malformed glob is dropped (never silently covers): an author's
            // typo must not make an undeclared write look declared.
            let pattern = glob::Pattern::new(&entry).ok()?;
            Some(Self::Glob {
                pattern,
                dir_prefix,
            })
        } else {
            Some(Self::Scope { scope: entry })
        }
    }

    fn covers(&self, path: &str) -> bool {
        match self {
            Self::Scope { scope } => path_is_inside_scope(path, scope),
            Self::Glob {
                pattern,
                dir_prefix,
            } => {
                pattern.matches_with(path, GLOB_MATCH_OPTIONS)
                    || dir_prefix
                        .as_deref()
                        .is_some_and(|dir| path_is_inside_scope(path, dir))
            }
        }
    }
}

/// Glob options that make `*`/`?` respect path separators (so `out/*.txt` matches
/// `out/a.txt` but NOT `out/sub/a.txt`) while `**` still spans directories.
const GLOB_MATCH_OPTIONS: glob::MatchOptions = glob::MatchOptions {
    case_sensitive: true,
    require_literal_separator: true,
    require_literal_leading_dot: false,
};

/// True when `path` equals `scope` or lies inside the `scope/` directory. Mirrors
/// `runner::dispatch::path_is_inside_owned_scope`.
fn path_is_inside_scope(path: &str, scope: &str) -> bool {
    path == scope
        || path
            .strip_prefix(scope)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

/// Normalize a repo-relative path/pattern for comparison: trim, drop a leading
/// `./`, and collapse a leading `/` (an absolute-looking entry is treated
/// repo-relative). Backslashes are left untouched — worktree paths are POSIX.
fn normalize_relative(value: &str) -> String {
    let trimmed = value.trim();
    let trimmed = trimmed.strip_prefix("./").unwrap_or(trimmed);
    trimmed.trim_start_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_observed_is_conforming_for_any_declaration() {
        let report = check_output_closure(&["out/*.txt"], &[] as &[&str]);
        assert!(report.is_conforming());
        assert!(report.undeclared.is_empty());
    }

    #[test]
    fn glob_covers_matching_file_and_flags_stray() {
        let report = check_output_closure(&["out/*.txt"], &["out/a.txt", "stray.bin"]);
        assert!(!report.is_conforming());
        assert_eq!(report.undeclared, vec![SmolStr::new("stray.bin")]);
    }

    #[test]
    fn single_star_does_not_cross_directory_boundary() {
        // `out/*.txt` must NOT cover a nested `out/sub/a.txt`.
        let report = check_output_closure(&["out/*.txt"], &["out/sub/a.txt"]);
        assert_eq!(report.undeclared, vec![SmolStr::new("out/sub/a.txt")]);
    }

    #[test]
    fn double_star_covers_nested_subtree() {
        let report = check_output_closure(
            &["out/**"],
            &["out/a.txt", "out/sub/b.txt", "out/sub/deep/c.rs"],
        );
        assert!(report.is_conforming(), "{report:?}");
        assert!(report.undeclared.is_empty());
    }

    #[test]
    fn plain_directory_scope_covers_subtree_but_not_siblings() {
        let report = check_output_closure(&["dist"], &["dist/app.js", "dist2/app.js"]);
        assert_eq!(report.undeclared, vec![SmolStr::new("dist2/app.js")]);
    }

    #[test]
    fn literal_file_path_covers_exact_match_only() {
        let report = check_output_closure(&["Cargo.lock"], &["Cargo.lock", "Cargo.toml"]);
        assert_eq!(report.undeclared, vec![SmolStr::new("Cargo.toml")]);
    }

    #[test]
    fn leading_dot_slash_and_absolute_are_normalized() {
        let report = check_output_closure(&["./out/*.txt"], &["/out/a.txt"]);
        assert!(report.is_conforming(), "{report:?}");
    }

    #[test]
    fn malformed_glob_never_silently_covers() {
        // An unmatched `[` is an invalid glob → dropped → the observed path is
        // flagged undeclared rather than silently accepted.
        let report = check_output_closure(&["out/[bad"], &["out/a.txt"]);
        assert_eq!(report.undeclared, vec![SmolStr::new("out/a.txt")]);
    }

    #[test]
    fn multiple_declarations_union_coverage() {
        let report = check_output_closure(
            &["src/**/*.rs", "Cargo.toml"],
            &["src/a.rs", "src/mod/b.rs", "Cargo.toml", "README.md"],
        );
        assert_eq!(report.undeclared, vec![SmolStr::new("README.md")]);
    }
}
