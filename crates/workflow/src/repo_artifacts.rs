//! What kata writes INTO the operator's own repository, as one enumerable list.
//!
//! # Why this exists
//!
//! kata points its execution-workspace provider at a repository the operator
//! owns (`vcs.jj_repo`; `kata init` writes `jj_repo = ".."`, i.e. the operator's
//! project root) and materializes its own state *inside* that tree — jj
//! metadata, per-execution candidate workspaces, and the node's whole durable data directory.
//!
//! Every one of those roots must be VCS-ignored in the target repo — a
//! requirement stated in a comment and an advisory string is not a check, and
//! an unchecked one lets a run promote kata's internals into a repository's
//! trunk while reporting `status=completed`.
//!
//! # Two kinds of root, and why both are here
//!
//! **Provider-determined** roots are what the jj execution-workspace provider —
//! the only one — writes, answered by
//! [`repo_local_artifact_roots`]: `.jj/` and `agents/`.
//!
//! **Config-determined** roots are free paths an operator sets, which land
//! inside the repository only for the layouts that put them there.
//! [`repo_local_artifact_paths`] composes those onto the provider set. Today
//! there is exactly one: `node.data_dir`.
//!
//! ## The data directory is the one that actually lands
//!
//! `kata init` renders `data_dir = "data"` relative to the config directory, so
//! a `kata init --config <repo>/.kata/kata.toml` project keeps **the node's
//! entire durable state inside the operator's repository** at `<repo>/.kata/data`
//! — `operational.db`, `cas.db` + `cas/`, `memory.db`, `stage_cache.db`, `main.lock`,
//! `recovery-generations/**`. (The shipped `config/kata.example.toml` puts it at
//! `~/.kata/data`, outside any repo; the generated one does not.)
//!
//! On a repository where the operator applied only `/.jj/` and `/agents/`, one
//! `kata serve` leaves `jj status` at the repo root showing **the whole
//! `.kata/data` tree as `A`dded to the working copy**, ledger and CAS included —
//! which is why the data directory is part of the declared set.
//!
//! # Naming
//!
//! Each root's NAME is owned by the code that creates it — [`AGENTS_DIR_NAME`]
//! and [`JJ_METADATA_DIR_NAME`] in `kata-vcs` — and this module only composes
//! them. Nothing retypes a path literal.

use std::path::Path;

use kata_types::config::VcsConfig;
use kata_vcs::{AGENTS_DIR_NAME, JJ_METADATA_DIR_NAME};

/// The repository-root-relative directories the jj execution-workspace provider
/// materializes inside the operator's target repository.
///
/// Slash-separated and relative to `vcs.jj_repo`. Callers that need to ask git
/// about them must query a path *inside* each directory rather than the
/// directory name itself — see `kata doctor`'s `target_repo_ignore` row for why
/// (`git check-ignore .jj` answers "not ignored" against the pattern `.jj/`
/// whenever the directory does not exist on disk yet).
///
/// This is the PROVIDER half only. Callers holding a config should use
/// [`repo_local_artifact_paths`], which adds the config-determined roots.
///
/// `JjBackend::open` colocates or adopts git in place, creating `.jj/` at the
/// repo root; the first execution adds `agents/<exec>/` beside it.
#[must_use]
pub fn repo_local_artifact_roots() -> &'static [&'static str] {
    &[JJ_METADATA_DIR_NAME, AGENTS_DIR_NAME]
}

/// Every repository-root-relative path kata materializes inside `vcs.jj_repo`
/// for THIS config: the backend roots plus the config-determined ones.
///
/// `data_dir` is `node.data_dir` as `ConfigManager` resolved it (absolute). It
/// contributes a root only when it actually lands inside `vcs.jj_repo` and is
/// not already covered by a backend root — an operator whose data directory is
/// `~/.kata/data` (the shipped example config's spelling) writes nothing extra
/// into the repository and must not be refused for a path they never create.
///
/// Order is stable: backend roots first, in declaration order, then the
/// config-determined ones. Consumers zip this against per-path answers.
#[must_use]
pub fn repo_local_artifact_paths(vcs: &VcsConfig, data_dir: &Path) -> Vec<String> {
    let backend_roots = repo_local_artifact_roots();
    let mut paths: Vec<String> = backend_roots
        .iter()
        .map(|root| (*root).to_string())
        .collect();

    if let Some(rel) = repo_relative(&vcs.jj_repo, data_dir)
        && !rel.is_empty()
        && !paths
            .iter()
            .any(|root| rel == *root || rel.starts_with(&format!("{root}/")))
    {
        paths.push(rel);
    }

    paths
}

/// `path` expressed relative to `repo` with `/` separators, or `None` when it is
/// not inside `repo`.
///
/// Tries the paths as given first and falls back to canonicalized forms, because
/// a config can name a repo through a symlink (`/tmp` is one on macOS) while the
/// data directory is spelled through the resolved path, or vice versa — and a
/// prefix test on two different spellings of the same directory answers "not
/// inside" for a path that is.
fn repo_relative(repo: &Path, path: &Path) -> Option<String> {
    let render = |rel: &Path| {
        rel.components()
            .map(|component| component.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/")
    };
    if let Ok(rel) = path.strip_prefix(repo) {
        return Some(render(rel));
    }
    let repo = repo.canonicalize().ok()?;
    let path = path.canonicalize().ok()?;
    path.strip_prefix(&repo).ok().map(render)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn vcs_at(repo: &Path) -> VcsConfig {
        VcsConfig {
            jj_repo: repo.to_path_buf(),
            ..VcsConfig::default()
        }
    }

    /// Every root must be repo-root-RELATIVE and non-empty: the consumer joins
    /// it onto `vcs.jj_repo` and feeds it to `git check-ignore`, where an
    /// absolute path is rejected outright and an empty one silently matches
    /// nothing.
    #[test]
    fn every_declared_root_is_a_relative_non_empty_path() {
        let roots = repo_local_artifact_roots();
        assert!(
            !roots.is_empty(),
            "the jj provider declares no artifact roots"
        );
        for root in roots {
            assert!(!root.is_empty(), "an empty root is declared");
            assert!(
                !root.starts_with('/'),
                "root {root:?} is absolute; roots are repo-relative"
            );
            assert!(
                !root.ends_with('/'),
                "root {root:?} has a trailing slash; consumers join onto it"
            );
        }
    }

    /// The roots are the SAME strings the creating code uses. Asserting the
    /// literal here would just be a second hand-kept copy — the copy this
    /// module exists to prevent — so this asserts the identity instead.
    #[test]
    fn the_roots_are_the_constants_the_jj_backend_creates_from() {
        assert_eq!(
            repo_local_artifact_roots(),
            &[JJ_METADATA_DIR_NAME, AGENTS_DIR_NAME],
        );
    }

    /// REGRESSION. `kata init` renders `data_dir = "data"` beside the config,
    /// so a `<repo>/.kata/kata.toml` project keeps `operational.db`, `cas/`,
    /// `memory.db` and `recovery-generations/**` INSIDE the operator's
    /// repository, and the declared set must name it.
    ///
    /// COUNTERFACTUAL: drop the `data_dir` arm from [`repo_local_artifact_paths`]
    /// and this goes red.
    #[test]
    fn a_data_dir_inside_the_repo_is_declared() {
        let repo = PathBuf::from("/srv/project");
        let paths = repo_local_artifact_paths(&vcs_at(&repo), &repo.join(".kata").join("data"));
        assert!(
            paths.contains(&".kata/data".to_string()),
            "a data dir inside the repository must be declared; got {paths:?}"
        );
        // The provider roots are still all there, in order, ahead of it.
        assert_eq!(
            &paths[..2],
            &[
                JJ_METADATA_DIR_NAME.to_string(),
                AGENTS_DIR_NAME.to_string()
            ],
        );
    }

    /// The other arm, so the rule is not satisfiable by always declaring: the
    /// shipped example config puts `data_dir` at `~/.kata/data`, outside every
    /// repository. Declaring a root for it would refuse operators for a path
    /// they never create — a refused set wider than the claim.
    #[test]
    fn a_data_dir_outside_the_repo_is_not_declared() {
        let repo = PathBuf::from("/srv/project");
        let paths = repo_local_artifact_paths(&vcs_at(&repo), Path::new("/home/op/.kata/data"));
        assert_eq!(
            paths,
            repo_local_artifact_roots()
                .iter()
                .map(|root| (*root).to_string())
                .collect::<Vec<_>>(),
            "a data dir outside the repository contributes nothing"
        );
    }

    /// A data dir NESTED under a provider root is already covered by that root's
    /// answer, and probing it twice would print the same verdict twice and let a
    /// remedy name a redundant pattern.
    #[test]
    fn a_data_dir_under_a_backend_root_is_not_declared_twice() {
        let repo = PathBuf::from("/srv/project");
        let paths =
            repo_local_artifact_paths(&vcs_at(&repo), &repo.join(AGENTS_DIR_NAME).join("state"));
        assert_eq!(
            paths.len(),
            repo_local_artifact_roots().len(),
            "a data dir inside an already-declared root adds nothing; got {paths:?}"
        );
    }

    /// A data dir that IS the repository root has no repo-relative path to
    /// probe, and asking git about the empty string matches nothing while
    /// reading as an answer.
    #[test]
    fn a_data_dir_that_is_the_repo_root_declares_no_empty_path() {
        let repo = PathBuf::from("/srv/project");
        let paths = repo_local_artifact_paths(&vcs_at(&repo), &repo);
        assert!(
            paths.iter().all(|path| !path.is_empty()),
            "no declared path may be empty; got {paths:?}"
        );
        assert_eq!(paths.len(), repo_local_artifact_roots().len());
    }
}
