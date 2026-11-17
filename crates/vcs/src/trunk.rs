//! Which branch is this repository's TRUNK — the one name kata INHERITS from
//! the host and never guesses.
//!
//! # The principle
//!
//! The operator decides which branch their workflow agents run on, on the host
//! they run workflows on.
//!
//! kata therefore has no opinion about trunk. It asks the repository, and when
//! the repository does not give one answer it **REFUSES** — it does not fall
//! back to a literal, because a wrong trunk is not a degraded mode. It is the
//! shape of every one of the failures below.
//!
//! # Why a hard-coded `"main"` is wrong
//!
//! On a `master`/`develop`/`release/next` repository
//! (`crates/vcs/tests/host_binding_known_red.rs`) a hard-coded `"main"` base
//! bookmark that is silently skipped when absent forks the execution workspace
//! from jj's EMPTY ROOT: the agent sees **none of the repository**, the recorded
//! identity claims `base_ref = "main"` — a bookmark that repository never had —
//! and the run fails only at its last stage, after spending whatever the agent
//! spent.
//!
//! # Why git's `HEAD` is DISQUALIFIED as a source, measured
//!
//! `git symbolic-ref --short HEAD` is wrong in three different directions
//! (measured with git 2.43.0):
//!
//! | repository shape | `symbolic-ref --short HEAD` | what it should say |
//! |---|---|---|
//! | `git init -b master`, **zero commits** | `master`, exit 0 | there is no trunk yet — `refs/heads/` is EMPTY |
//! | trunk `master`, operator on `feature/x` | `feature/x` | `master` |
//! | detached HEAD | exit 128 | (unchanged) |
//!
//! The second row is the damaging one: kata would fork from, and PROMOTE INTO,
//! whatever branch the operator happened to have checked out.
//!
//! And on the jj side `HEAD` is not merely a poor signal, it is a **frozen**
//! one. jj-lib's `git::export_some_refs` runs `check_and_detach_head`, which
//! detaches a symbolic `.git/HEAD` at its PRE-move commit whenever an export
//! moves the bookmark HEAD points at. kata's first `promote` exports
//! `refs/heads/<trunk>`, so `.git/HEAD` becomes a raw sha and never moves again.
//! `JjBackend::refresh_trunk_from_git`'s own doc records that it deliberately
//! does not key off git `HEAD` for exactly this reason.
//!
//! # The precedence
//!
//! 1. **[`TrunkSource::Configured`]** — `vcs.trunk`. The operator said so; that
//!    ends the question. This is the "the operator decides" arm.
//! 2. **[`TrunkSource::RemoteHead`]** — the branch the remote's `HEAD` symbolic
//!    ref names (`refs/remotes/origin/HEAD` → `refs/remotes/origin/<name>`),
//!    when that branch also exists locally. This is the forge's own answer to
//!    "what is the default branch", written by `git clone` and by
//!    `git remote set-head`, and it is a value kata never writes.
//! 3. **[`TrunkSource::SoleLocalBranch`]** — exactly one local branch that kata
//!    does not own. One candidate is not a guess.
//! 4. **REFUSE.** Zero candidates is [`TrunkResolution::NoTrunkYet`] (there is
//!    genuinely nothing to fork from, which is a legitimate state for a fresh
//!    repository); two or more is an error naming both remedies.
//!
//! # The rank-3 trap, and why the exclusion set is DERIVED
//!
//! A naive "exactly one local branch" resolves cleanly on a fresh repository and
//! then refuses forever, because kata's own refs accumulate in the repository it
//! is working in: `exec-<ulid>` per `commit`, `parked/<…>` per `park` and per
//! fail-closed landing arm, `kata/<ulid>` per `forge_export` — on a busy
//! repository, dozens of them.
//!
//! So rank 3 excludes kata's own refs — and the prefixes it excludes are the
//! CONSTANTS THE MINTING CODE USES ([`PARKED_REF_PREFIX`],
//! [`EXECUTION_REF_PREFIX`], [`FORGE_BRANCH_PREFIX`]), never retyped here. The
//! precedent is `kata_workflow::repo_artifacts::repo_local_artifact_roots`,
//! which composes `kata doctor`'s probe paths out of the constants that create
//! those directories for the same reason.
//!
//! # What the exclusion set does NOT rescue, measured
//!
//! A repository with hundreds of branches kata did not mint and **no**
//! `refs/remotes/origin/HEAD` (`git symbolic-ref refs/remotes/origin/HEAD` →
//! exit 128) resolves at rank 4: **REFUSED**, until the operator sets
//! `vcs.trunk` or runs `git remote set-head origin -a`. That is the design
//! working, not a gap in it — kata will not pick one of hundreds of branches to
//! land an agent's work onto.

use kata_types::{KataError, KataResult};

/// Prefix of every ref kata parks a candidate under (`parked/<label>`).
///
/// Read by [`is_kata_owned_ref`] and by every site that MINTS a parked ref, so
/// the resolver's exclusion set and the naming scheme cannot drift apart.
pub const PARKED_REF_PREFIX: &str = "parked/";

/// Prefix of every per-execution candidate ref (`exec-<ulid>`) — the jj bookmark
/// `commit` workspace effect publishes.
pub const EXECUTION_REF_PREFIX: &str = "exec-";

/// Prefix of every branch `forge_export` pushes (`kata/<ulid>`).
pub const FORGE_BRANCH_PREFIX: &str = "kata/";

/// Every ref-name prefix kata itself mints inside the operator's repository.
///
/// Derived from the three constants above rather than restated, so adding a
/// fourth kata-minted ref shape is one edit and cannot leave the trunk resolver
/// counting it as an operator branch.
pub const KATA_OWNED_REF_PREFIXES: &[&str] =
    &[PARKED_REF_PREFIX, EXECUTION_REF_PREFIX, FORGE_BRANCH_PREFIX];

/// Whether `name` is a branch/bookmark KATA created in the operator's
/// repository, and therefore not a candidate for trunk.
///
/// Names are compared WHOLE, never split on `/`: `release/next` is a legal git
/// branch name and a legal jj bookmark name, and a resolver that split on `/`
/// would classify it by its first segment.
#[must_use]
pub fn is_kata_owned_ref(name: &str) -> bool {
    KATA_OWNED_REF_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// Where a resolved trunk name came from. Recorded so an operator reading a
/// refusal or a doctor row can see WHICH question kata asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrunkSource {
    /// `vcs.trunk` — the operator stated it.
    Configured,
    /// The remote's `HEAD` symbolic ref, and the branch exists locally.
    RemoteHead,
    /// The one local branch kata does not own.
    SoleLocalBranch,
}

impl TrunkSource {
    /// Stable, operator-facing label (doctor details, log fields).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Configured => "configured",
            Self::RemoteHead => "remote_head",
            Self::SoleLocalBranch => "sole_local_branch",
        }
    }
}

/// What a repository answers when kata asks which branch is trunk.
///
/// TWO outcomes, deliberately — this is the split that makes the fix visible.
/// The shipped code had ONE `None` arm returning `Ok(())`, which conflated "this
/// repository has nothing to fork yet" (true, harmless) with "this repository's
/// trunk is called something else" (false, and the cause of every measured
/// failure). A third state, "kata cannot tell", is not a variant at all: it is
/// an `Err`, because continuing past it is what the defect did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrunkResolution {
    /// This repository's trunk, and which question answered.
    Resolved {
        /// The plain branch/bookmark name — never a `refs/heads/` path.
        name: String,
        /// Which rank of the precedence produced it.
        source: TrunkSource,
    },
    /// The repository holds no branch kata could fork from or land onto: a
    /// fresh `git init` / `jj git init --colocate` before anything has landed.
    ///
    /// Legitimately `Ok` for creating a workspace (jj's empty-root checkout IS
    /// the right base when there is no history). NOT `Ok` for landing — see
    /// [`Self::require`].
    NoTrunkYet,
}

impl TrunkResolution {
    /// The resolved name, or `None` when there is no trunk yet.
    ///
    /// This is the value that may be stamped as DURABLE EVIDENCE
    /// (`ExecutionWorkspaceIdentity::base_ref`). `None` records "kata does not
    /// know this repository's trunk", which is a true statement; a constant
    /// would have recorded a false one.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Resolved { name, .. } => Some(name.as_str()),
            Self::NoTrunkYet => None,
        }
    }

    /// The resolved name, or a typed refusal naming `operation`.
    ///
    /// For the operations that cannot mean anything without a trunk: landing a
    /// candidate, resolving a forge-export base.
    pub fn require(&self, operation: &str) -> KataResult<&str> {
        self.name().ok_or_else(|| {
            KataError::Validation(format!(
                "{operation}: this repository has no trunk yet — it holds no branch that kata \
                 did not create itself, so there is nothing to base on. Create the trunk \
                 branch, or name it with `vcs.trunk` in kata.toml once it exists"
            ))
        })
    }
}

/// The facts about a repository the resolver decides from.
///
/// Gathered from the backend's own surface (jj's view + the colocated `.git`)
/// and then judged by ONE policy, so no second observer can answer differently
/// for the same repository.
#[derive(Clone, Debug, Default)]
pub struct TrunkObservation {
    /// `vcs.trunk` verbatim, when the operator set one.
    pub configured: Option<String>,
    /// EVERY local branch/bookmark name the repository holds, kata's own refs
    /// included. The kata-owned exclusion is applied by [`resolve_trunk`], not
    /// by the observer, so no observer can filter differently.
    pub local_branches: Vec<String>,
    /// The plain branch name the remote's `HEAD` symbolic ref points at
    /// (`refs/remotes/origin/HEAD` → `refs/remotes/origin/develop` ⇒
    /// `"develop"`), when the repository has one.
    pub remote_head: Option<String>,
}

impl TrunkObservation {
    /// The local branches kata did not create, sorted and deduplicated.
    ///
    /// The rank-3 candidate set, and the list a refusal message shows.
    #[must_use]
    pub fn candidates(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self
            .local_branches
            .iter()
            .map(|name| name.trim())
            .filter(|name| !name.is_empty() && !is_kata_owned_ref(name))
            .collect();
        names.sort_unstable();
        names.dedup();
        names
    }

    fn holds(&self, name: &str) -> bool {
        self.local_branches
            .iter()
            .any(|candidate| candidate.trim() == name)
    }
}

/// How many candidate names a refusal lists before it truncates. A message that
/// prints 250 branch names is a message nobody reads.
const REFUSAL_SAMPLE: usize = 8;

/// Resolve `observed` to this repository's trunk, or REFUSE.
///
/// Pure: every fact comes from `observed`, so the precedence is unit-testable
/// without a repository and both backends provably share it. See the module doc
/// for the precedence and why each rank is where it is.
pub fn resolve_trunk(observed: &TrunkObservation) -> KataResult<TrunkResolution> {
    // Rank 1 — the operator stated it. Checked against the WHOLE branch list,
    // not the kata-owned-filtered candidates: the exclusion set exists to
    // disambiguate a guess, and rank 1 is not a guess. An operator who names
    // `exec-…` as their trunk is doing something strange on purpose.
    if let Some(configured) = observed
        .configured
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if observed.holds(configured) {
            return Ok(TrunkResolution::Resolved {
                name: configured.to_owned(),
                source: TrunkSource::Configured,
            });
        }
        if observed.candidates().is_empty() {
            // Nothing the OPERATOR made yet — the configured name is a statement
            // about a future branch, not a mismatch. Forking from the empty root
            // is correct here; landing still refuses via `require`.
            //
            // The guard is over CANDIDATES, not over `local_branches`. Keyed on
            // the latter it would hold only until kata minted its own first
            // `exec-` or `parked/` ref, after which the identical future-branch
            // state would become a hard refusal — so `vcs.trunk`, the refusal's
            // own recommended remedy, would work exactly once per repository.
            return Ok(TrunkResolution::NoTrunkYet);
        }
        return Err(KataError::Validation(format!(
            "vcs.trunk = \"{configured}\" names a branch this repository does not have. It \
             holds: {}. Fix `vcs.trunk` in kata.toml, or create that branch — kata will not \
             fall back to another one, because forking an agent from the wrong base spends \
             real budget before anything notices",
            sample(&observed.candidates())
        )));
    }

    let candidates = observed.candidates();

    // Rank 2 — the remote's own answer. Required to exist LOCALLY as well: the
    // fork and the land both operate on a local ref, so a remote default branch
    // that was never fetched is a name kata cannot act on.
    if let Some(remote_head) = observed
        .remote_head
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        && candidates.contains(&remote_head)
    {
        return Ok(TrunkResolution::Resolved {
            name: remote_head.to_owned(),
            source: TrunkSource::RemoteHead,
        });
    }

    // Rank 3 / 4.
    match candidates.as_slice() {
        [] => Ok(TrunkResolution::NoTrunkYet),
        [only] => Ok(TrunkResolution::Resolved {
            name: (*only).to_owned(),
            source: TrunkSource::SoleLocalBranch,
        }),
        many => Err(KataError::Validation(format!(
            "cannot tell which branch is this repository's trunk: it has {} branches kata did \
             not create ({}) and no `refs/remotes/origin/HEAD` naming a default. kata will not \
             guess — an agent forked from the wrong base spends real budget and fails at its \
             last stage. Either set `vcs.trunk = \"<branch>\"` in kata.toml, or tell git which \
             one is the default with `git remote set-head origin -a` (or \
             `git remote set-head origin <branch>` offline)",
            many.len(),
            sample(many)
        ))),
    }
}

/// `a, b, c (+N more)` — bounded so a repository with hundreds of branches
/// produces a readable refusal.
fn sample(names: &[&str]) -> String {
    if names.is_empty() {
        // An empty list rendered as "" produced the refusal "It holds: ." — a
        // malformed sentence at the moment an operator most needs a legible one.
        return "(none)".to_string();
    }
    let shown = names
        .iter()
        .take(REFUSAL_SAMPLE)
        .copied()
        .collect::<Vec<_>>()
        .join(", ");
    if names.len() > REFUSAL_SAMPLE {
        format!("{shown} (+{} more)", names.len() - REFUSAL_SAMPLE)
    } else {
        shown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed(branches: &[&str]) -> TrunkObservation {
        TrunkObservation {
            configured: None,
            local_branches: branches.iter().map(|name| (*name).to_owned()).collect(),
            remote_head: None,
        }
    }

    #[test]
    fn the_exclusion_set_is_exactly_the_three_minting_prefixes() {
        assert_eq!(
            KATA_OWNED_REF_PREFIXES,
            &[PARKED_REF_PREFIX, EXECUTION_REF_PREFIX, FORGE_BRANCH_PREFIX],
        );
        assert!(is_kata_owned_ref("parked/01ARZ3"));
        assert!(is_kata_owned_ref("exec-01ARZ3"));
        assert!(is_kata_owned_ref("kata/01ARZ3"));
        assert!(!is_kata_owned_ref("main"));
        // NOT split on `/`: a slash-carrying operator branch is an operator
        // branch, and `kata-tools/...` is not `kata/...`.
        assert!(!is_kata_owned_ref("release/next"));
        assert!(!is_kata_owned_ref("kata-tools/x"));
        assert!(!is_kata_owned_ref("parked-by-hand"));
    }

    #[test]
    fn configured_wins_over_every_other_signal() {
        let mut obs = observed(&["main", "develop"]);
        obs.configured = Some("develop".to_owned());
        obs.remote_head = Some("main".to_owned());
        assert_eq!(
            resolve_trunk(&obs).unwrap(),
            TrunkResolution::Resolved {
                name: "develop".to_owned(),
                source: TrunkSource::Configured,
            }
        );
    }

    #[test]
    fn configured_but_absent_is_a_refusal_not_a_fallback() {
        let mut obs = observed(&["main", "develop"]);
        obs.configured = Some("trunk".to_owned());
        let err = resolve_trunk(&obs).unwrap_err().to_string();
        assert!(err.contains("vcs.trunk = \"trunk\""), "{err}");
        assert!(
            err.contains("main, develop") || err.contains("develop, main"),
            "{err}"
        );
    }

    #[test]
    fn configured_on_a_repo_with_no_branches_is_nothing_to_fork_yet() {
        let mut obs = observed(&[]);
        obs.configured = Some("main".to_owned());
        assert_eq!(resolve_trunk(&obs).unwrap(), TrunkResolution::NoTrunkYet);
    }

    #[test]
    fn a_configured_trunk_stays_nothing_to_fork_after_kata_mints_its_own_refs() {
        // The bootstrap flow must work more than ONCE. With the guard over
        // `local_branches`, kata's own first `exec-`/`parked/` ref would make the
        // repository non-empty, so this identical future-branch state would flip from
        // NoTrunkYet to a hard refusal — and the refusal's recommended remedy is
        // `vcs.trunk`, which is already set here.
        let mut obs = observed(&["exec-01REVIEWPROBE", "parked/01REVIEWPROBE"]);
        obs.configured = Some("main".to_owned());
        assert_eq!(resolve_trunk(&obs).unwrap(), TrunkResolution::NoTrunkYet);
    }

    #[test]
    fn a_refusal_over_no_candidates_at_all_still_renders_a_sentence() {
        // `sample(&[])` returned "", so the refusal read "It holds: ." — malformed at
        // the moment an operator most needs it legible.
        assert_eq!(sample(&[]), "(none)");
    }

    #[test]
    fn remote_head_outranks_a_multi_branch_repository() {
        let mut obs = observed(&["main", "develop", "feature/x"]);
        obs.remote_head = Some("develop".to_owned());
        assert_eq!(
            resolve_trunk(&obs).unwrap(),
            TrunkResolution::Resolved {
                name: "develop".to_owned(),
                source: TrunkSource::RemoteHead,
            }
        );
    }

    #[test]
    fn a_remote_head_that_is_not_local_does_not_resolve() {
        // The fork and the land both act on a LOCAL ref.
        let mut obs = observed(&["main", "develop"]);
        obs.remote_head = Some("release/next".to_owned());
        let err = resolve_trunk(&obs).unwrap_err().to_string();
        assert!(err.contains("kata will not guess"), "{err}");
    }

    #[test]
    fn the_sole_non_kata_branch_resolves_after_kata_refs_accumulate() {
        // THE RANK-3 TRAP: a naive "exactly one branch" resolver is green on the
        // first arm and refuses forever on the second.
        assert_eq!(
            resolve_trunk(&observed(&["master"])).unwrap(),
            TrunkResolution::Resolved {
                name: "master".to_owned(),
                source: TrunkSource::SoleLocalBranch,
            }
        );
        assert_eq!(
            resolve_trunk(&observed(&[
                "master",
                "exec-01ARZ3NDEKTSV4RRFFQ69G5FAV",
                "parked/01ARZ3NDEKTSV4RRFFQ69G5FAV",
                "kata/01ARZ3NDEKTSV4RRFFQ69G5FAV",
            ]))
            .unwrap(),
            TrunkResolution::Resolved {
                name: "master".to_owned(),
                source: TrunkSource::SoleLocalBranch,
            }
        );
    }

    #[test]
    fn a_repository_of_only_kata_refs_has_no_trunk_yet() {
        assert_eq!(
            resolve_trunk(&observed(&["exec-01ARZ3", "parked/01ARZ3"])).unwrap(),
            TrunkResolution::NoTrunkYet
        );
    }

    #[test]
    fn ambiguity_refuses_and_names_both_remedies() {
        let err = resolve_trunk(&observed(&["main", "develop"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("vcs.trunk"), "{err}");
        assert!(err.contains("git remote set-head origin"), "{err}");
    }

    #[test]
    fn a_refusal_over_hundreds_of_branches_stays_readable() {
        let names: Vec<String> = (0..250).map(|n| format!("topic/{n:03}")).collect();
        let obs = TrunkObservation {
            configured: None,
            local_branches: names,
            remote_head: None,
        };
        let err = resolve_trunk(&obs).unwrap_err().to_string();
        assert!(err.contains("250 branches"), "{err}");
        assert!(err.contains("+242 more"), "{err}");
        assert!(err.len() < 700, "refusal is {} bytes: {err}", err.len());
    }

    #[test]
    fn require_refuses_when_there_is_no_trunk_and_names_the_operation() {
        let err = TrunkResolution::NoTrunkYet
            .require("promote")
            .unwrap_err()
            .to_string();
        assert!(err.contains("promote"), "{err}");
        assert_eq!(
            TrunkResolution::Resolved {
                name: "main".to_owned(),
                source: TrunkSource::Configured,
            }
            .require("promote")
            .unwrap(),
            "main"
        );
    }

    /// `name()` is what gets stamped into durable evidence, so it must be the
    /// resolved value or nothing — never a constant.
    #[test]
    fn no_trunk_yet_stamps_nothing() {
        assert_eq!(TrunkResolution::NoTrunkYet.name(), None);
    }
}
