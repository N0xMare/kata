//! WHO does kata commit as — the one identity kata INHERITS from the host and
//! never invents.
//!
//! # The principle
//!
//! kata does not decide identity for people: by default it uses git with
//! whatever credentials the host it runs on already has (a standard ssh key,
//! the `gh` CLI, and so on).
//!
//! kata therefore has no opinion about who the operator is. It asks the host,
//! and when the host does not answer it **REFUSES**. It does not fabricate, and
//! it does not fall back — a wrong author is not a degraded mode, it is a
//! commit that reaches the operator's forge attributed to nobody.
//!
//! # The mint surfaces this module covers
//!
//! 1. jj's defaults: `UserSettings::from_config(StackedConfig::with_defaults())`
//!    is exactly ONE layer (MEASURED), jj-lib's own `config/misc.toml`, which
//!    sets `user.name` and `user.email` to the EMPTY STRING — a commit authored
//!    on it reaches git as `JJ_EMPTY_STRING <JJ_EMPTY_STRING>`.
//! 2. A FABRICATED identity (`git -c user.name=kata -c user.email=…`) is worse
//!    than none, because no empty-identity refusal will ever fire on it; and
//!    without `commit.gpgsign=false` a host with a signing key would SIGN it WITH
//!    THE OPERATOR'S KEY — discarding the host's identity and inheriting its
//!    signing key, inverted on both halves. kata's posture is the reverse: it
//!    inherits the identity, which is an attribution, and never the signing
//!    key, because a signature is an assertion a downstream verifier may
//!    trust, nor the hooks, which are operator code that did not consent to
//!    running in a candidate worktree. Its git calls state the last two
//!    through `kata_types::git_policy::GIT_EXECUTION_OVERRIDES`.
//! 3. **The push side.** MEASURED: `jj git push` refuses a commit with no author
//!    — *"Won't push commit … since it has no author and/or committer set"* — but
//!    that refusal lives in jj-**CLI**, and kata shells `git push` at the
//!    colocated root, so the guardrail never runs: an authorless commit reaches a
//!    real remote at exit 0.
//!
//! # ASK THE TOOL, NEVER PARSE ITS FILES
//!
//! Both tools make ONE config file yield DIFFERENT identities per repository,
//! and both are invisible to a naive read. Measured:
//!
//! | mechanism | one file, two repositories | what a naive file read says |
//! |---|---|---|
//! | git `includeIf "gitdir:…"` | `work@example.test` / `default@example.test` | `default@example.test` for both |
//! | jj `[[--scope]] --when.repositories` | `jjscoped@…` / `jjdefault@…` | `jjdefault@…` for both |
//!
//! So the question is asked of a PROCESS, not of a path.
//!
//! # WHY GIT AND NOT JJ — the judgement, and the cost it carries
//!
//! **MEASURED: jj does NOT read git's `user.name` / `user.email`.** A `$HOME` holding only a
//! `~/.gitconfig` with a name and email produces, from a real `jj 0.39.0`
//! binary, `AUTHOR=[] EMAIL=[]`. `jj-lib` does ZERO config path discovery; every
//! path rule lives in jj-CLI, which kata does not use. So "load the layers
//! jj-cli loads" is NECESSARY AND NOT SUFFICIENT: on a normal Linux host the
//! host's answer to *who am I to git* lives in git config.
//!
//! Asking jj would mean either shelling the `jj` binary or re-implementing
//! jj-CLI's path discovery in process. **kata asks GIT**, for four reasons:
//!
//! 1. **The principle names git**: use git with whatever credentials the host
//!    has.
//! 2. **git is ALREADY a production host-tool dependency.**
//!    `JjBackend::push_forge_branch_expecting` shells `git push` at the colocated root and
//!    its own error text says so. **jj is not a host dependency at all** — kata pins
//!    `jj-lib` as a LIBRARY and never spawns `jj`. Making the identity depend on
//!    a `jj` binary would mean an operator with no jj installed cannot commit on
//!    the DEFAULT backend, and would add `jj` to the gate's irreducible host-tool
//!    list (`just host-check`).
//! 3. **ONE resolver keeps every caller answering the same way.** Two
//!    resolvers (jj-config here, git-config there) would let the code path
//!    silently change WHO kata commits as in the same repository — the defect
//!    [`crate::trunk::resolve_trunk`] prevents one axis over.
//! 4. **`git var` is git's OWN resolution, refusal included.** It covers
//!    `GIT_AUTHOR_NAME`/`GIT_AUTHOR_EMAIL`, `EMAIL`, the system/global/local/
//!    worktree config layers and `includeIf` — none of which a
//!    `git config --get user.email` pair fully covers (measured: with the
//!    identity in the ENVIRONMENT only, `git config --get user.email` exits 1
//!    while `git var GIT_AUTHOR_IDENT` answers). And when there is no answer it
//!    fails with git's own words, so kata's refusal cannot drift from git's.
//!
//! **THE COST, stated rather than hidden.** An operator whose identity lives
//! ONLY in `~/.jjconfig.toml` and NOWHERE in git config is REFUSED, even
//! though the `jj` CLI would commit for them. That is a real narrowing. It is
//! the right one: what kata produces is a git commit that leaves the host
//! through `git push`, and git config is where a git host states who it is. The
//! refusal names the remedy.
//!
//! # The precedence
//!
//! 1. **git's answer for THIS repository** —
//!    `git -c user.useConfigOnly=true var GIT_AUTHOR_IDENT`, run at the
//!    repository root. One rank, because git's own precedence is inside it.
//! 2. **REFUSE.**
//!
//! There is deliberately no `vcs.identity` config key, and the asymmetry with
//! `vcs.trunk` is the argument for it: `vcs.trunk` exists because git has no
//! "which branch is trunk" knob beyond a remote `HEAD` many repositories lack.
//! git HAS an identity knob, several, and asking git means the operator's
//! existing one already works — including the per-repository ones. A kata
//! config key would be a SECOND place to state the same fact, which is the
//! shape that drifts.
//!
//! # Why `user.useConfigOnly=true`
//!
//! Without it git GUESSES: measured, a `$HOME` holding only `EMAIL=…` yields
//! `op <generic@example.test>`, where `op` came from the passwd gecos field and
//! nobody stated it. A guess is not the host's answer, and this one reaches the
//! operator's forge. `user.useConfigOnly` is git's own knob for exactly this,
//! and — measured — it suppresses only the guess: an identity stated in the
//! ENVIRONMENT still resolves under it.

use std::path::Path;

use crate::process::{LOCAL_COMMAND_TIMEOUT, VcsCommand};

use kata_types::commit_identity::{CommitIdentity, kata_minted_identity_reason};
use kata_types::{KataError, KataResult};

/// The git variable that carries git's OWN resolution of the author identity.
const GIT_AUTHOR_IDENT_VAR: &str = "GIT_AUTHOR_IDENT";

/// git's knob for "do not guess an identity from the passwd file and the
/// hostname" — see the module doc.
const NO_GUESSING: &str = "user.useConfigOnly=true";

/// The raw facts about a host the identity resolver decides from.
///
/// Gathered by [`observe_identity_at`], judged by [`resolve_commit_identity`].
/// Split for the same reason [`crate::trunk::TrunkObservation`] is split: the
/// policy is then unit-testable with no repository and no host at all, which is
/// the only way to test the REFUSAL — a host that has a git identity cannot
/// otherwise exercise the arm that matters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdentityObservation {
    /// Trimmed stdout of `git … var GIT_AUTHOR_IDENT` when git answered:
    /// `Name <email> <unix-seconds> <±hhmm>`.
    pub git_author_ident: Option<String>,
    /// git's own stderr when it did NOT answer, verbatim and trimmed. Quoted
    /// into the refusal so the operator reads git's words, not kata's paraphrase
    /// of them.
    pub git_refusal: Option<String>,
    /// The repository the question was asked about, for the refusal message.
    pub repo: String,
}

/// Ask GIT who commits in the repository at `repo_root`.
///
/// Shells `git`, never reads a config file — see the module doc's table. Runs
/// with `-C <repo_root>` so a per-repository `includeIf` resolves the way it
/// will for every other git invocation kata makes against that repository.
///
/// Non-failing by construction: every way of not getting an answer (git absent,
/// path absent, identity absent) lands in [`IdentityObservation::git_refusal`],
/// because this feeds a resolver whose whole job is to refuse when it has no
/// answer.
#[must_use]
pub fn observe_identity_at(repo_root: &Path) -> IdentityObservation {
    let repo = repo_root.display().to_string();
    let output = VcsCommand::new("git", &[], LOCAL_COMMAND_TIMEOUT)
        .arg("-C")
        .arg(repo_root)
        .arg("-c")
        .arg(NO_GUESSING)
        .arg("var")
        .arg(GIT_AUTHOR_IDENT_VAR)
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let answer = String::from_utf8_lossy(&out.stdout).trim().to_owned();
            if answer.is_empty() {
                IdentityObservation {
                    git_author_ident: None,
                    git_refusal: Some("`git var GIT_AUTHOR_IDENT` exited 0 with no output".into()),
                    repo,
                }
            } else {
                IdentityObservation {
                    git_author_ident: Some(answer),
                    git_refusal: None,
                    repo,
                }
            }
        }
        Ok(out) => IdentityObservation {
            git_author_ident: None,
            git_refusal: Some(first_line(&String::from_utf8_lossy(&out.stderr))),
            repo,
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => IdentityObservation {
            git_author_ident: None,
            git_refusal: Some("`git` was not found on PATH".into()),
            repo,
        },
        Err(err) => IdentityObservation {
            git_author_ident: None,
            git_refusal: Some(format!("could not run `git`: {err}")),
            repo,
        },
    }
}

/// Judge `observed`, or REFUSE.
///
/// Pure: every fact comes from `observed`, so the precedence is unit-testable
/// without a repository and both backends provably share it.
pub fn resolve_commit_identity(observed: &IdentityObservation) -> KataResult<CommitIdentity> {
    let Some(answer) = observed
        .git_author_ident
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(no_identity(observed, observed.git_refusal.as_deref()));
    };

    let Some(identity) = parse_git_ident(answer) else {
        return Err(no_identity(
            observed,
            Some(&format!(
                "`git var {GIT_AUTHOR_IDENT_VAR}` answered `{answer}`, which is not the \
                 `Name <email> <seconds> <±hhmm>` shape kata knows how to read"
            )),
        ));
    };

    if let Some(reason) = identity.minted_by_kata() {
        return Err(no_identity(
            observed,
            Some(&format!(
                "git answered `{}`, and kata refuses that identity because {reason}",
                identity.author_line()
            )),
        ));
    }

    Ok(identity)
}

/// The author line to stamp on a commit that is about to be PUBLISHED — parked,
/// promoted, or pushed to a forge — or a typed refusal naming `operation`.
///
/// This is the EXPORT-PATH half of the remedy, and it is a different question
/// from [`resolve_commit_identity`]. That one asks *does this host have an
/// answer* and is asked at admission, before work is placed or paid for. This
/// one asks *what does the commit in front of me actually carry*, and it needs
/// no host identity at all — which is why it still fires on a commit that was
/// minted by a different tool, or by an AGENT inside the wrap.
///
/// Both halves are required: a configured identity must show a non-placeholder
/// `%an <%ae>` on the git side, and a REFUSAL must fire on the
/// `forge_export` path and not at commit time alone, or the empty identity
/// still leaves the host by that route.
pub fn require_publishable_identity(
    operation: &str,
    commit_sha: &str,
    author_name: &str,
    author_email: &str,
    committer_name: &str,
    committer_email: &str,
) -> KataResult<String> {
    // BOTH roles, and the reason is a composition rather than symmetry for its own
    // sake. `git commit --amend` PRESERVES the prior author while replacing the
    // committer, so a check that reads only the author admits a commit whose content
    // was rewritten by something that could not author it — it would carry the
    // operator as author and kata's sandbox sentinel as committer, and survive
    // park/promote/forge_export. jj's rebase arms mint a fresh committer from
    // `user_settings` for the same reason, so a host identity that vanishes mid-run
    // lands `JJ_EMPTY_STRING` in the committer alone. Without the committer
    // check, "an agent-authored commit cannot survive a promote" would be true
    // only where the agent was the AUTHOR.
    for (role, name, email) in [
        ("author", author_name, author_email),
        ("committer", committer_name, committer_email),
    ] {
        if let Some(reason) = kata_minted_identity_reason(name, email) {
            return Err(KataError::Validation(format!(
                "{operation}: refusing to publish commit {commit_sha} — its {role} is \
                 `{name} <{email}>` and {reason}. kata commits as the operator or not at all: \
                 set a git identity for this repository (`git config user.email \
                 \"you@example.com\"` and `git config user.name \"Your Name\"`, or the same \
                 with `--global`) and re-run. Nothing was published"
            )));
        }
    }
    Ok(CommitIdentity::new(author_name, author_email).author_line())
}

/// The refusal, in one place so admission and every later caller phrase it
/// identically.
fn no_identity(observed: &IdentityObservation, detail: Option<&str>) -> KataError {
    let detail = detail.map_or_else(String::new, |value| format!(" ({value})"));
    KataError::Validation(format!(
        "kata has no identity to commit as in {}{detail}. kata INHERITS the host's git identity \
         and never invents one, so it refuses rather than authoring a commit attributed to \
         nobody. Set one — `git config user.email \"you@example.com\"` and \
         `git config user.name \"Your Name\"` inside that repository, or the same with \
         `--global` for every repository on this host. NOTE: an identity in `~/.jjconfig.toml` \
         alone does not answer this — kata asks git, because what it produces is a git commit \
         that leaves the host through `git push`",
        observed.repo,
    ))
}

/// `Name <email> 1787834600 -0400` → [`CommitIdentity`].
///
/// git's ident grammar forbids `<` and `>` inside the name, so the LAST `<` is
/// unambiguously the start of the email. The trailing `<seconds> <±hhmm>` is
/// dropped rather than parsed: the commit carries its own timestamp, and a
/// receipt that carried one would invite re-deriving the receipt from the
/// commit.
fn parse_git_ident(line: &str) -> Option<CommitIdentity> {
    let open = line.rfind('<')?;
    let close = line[open..].find('>')? + open;
    let name = line[..open].trim();
    let email = line[open + 1..close].trim();
    if name.is_empty() || email.is_empty() {
        return None;
    }
    Some(CommitIdentity::new(name, email))
}

/// First non-empty line of `text`, trimmed. git's identity refusal is a
/// fourteen-line essay; the first line is the sentence.
fn first_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("git gave no reason")
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answered(ident: &str) -> IdentityObservation {
        IdentityObservation {
            git_author_ident: Some(ident.to_owned()),
            git_refusal: None,
            repo: "/tmp/repo".to_owned(),
        }
    }

    #[test]
    fn gits_answer_is_the_identity() {
        let identity =
            resolve_commit_identity(&answered("A Person <person@example.com> 1787834600 -0400"))
                .expect("resolve");
        assert_eq!(identity.name, "A Person");
        assert_eq!(identity.email, "person@example.com");
        assert_eq!(identity.author_line(), "A Person <person@example.com>");
    }

    #[test]
    fn no_answer_refuses_and_quotes_gits_own_words() {
        let observed = IdentityObservation {
            git_author_ident: None,
            git_refusal: Some("Author identity unknown".to_owned()),
            repo: "/tmp/repo".to_owned(),
        };
        let err = resolve_commit_identity(&observed).expect_err("must refuse");
        let message = err.to_string();
        assert!(message.contains("Author identity unknown"), "{message}");
        assert!(message.contains("/tmp/repo"), "{message}");
        assert!(message.contains("git config user.email"), "{message}");
        // The jj narrowing is stated to the operator, not only in a doc comment.
        assert!(message.contains(".jjconfig.toml"), "{message}");
    }

    #[test]
    fn an_unparseable_answer_refuses_rather_than_guessing() {
        assert!(resolve_commit_identity(&answered("no angle brackets here")).is_err());
        assert!(resolve_commit_identity(&answered("<person@example.com> 1 +0000")).is_err());
        assert!(resolve_commit_identity(&answered("A Person <> 1 +0000")).is_err());
    }

    #[test]
    fn a_host_answering_with_a_kata_minted_identity_is_refused() {
        let observed = answered(&format!(
            "{} <{}> 1787834600 -0400",
            kata_types::commit_identity::SANDBOX_AGENT_NAME,
            kata_types::commit_identity::SANDBOX_AGENT_EMAIL,
        ));
        let err = resolve_commit_identity(&observed).expect_err("must refuse");
        assert!(err.to_string().contains("AGENT SANDBOX identity"), "{err}");
    }

    #[test]
    fn a_name_containing_an_at_sign_still_parses() {
        let identity = resolve_commit_identity(&answered("a@b <person@example.com> 1 +0000"))
            .expect("resolve");
        assert_eq!(identity.name, "a@b");
        assert_eq!(identity.email, "person@example.com");
    }

    #[test]
    fn publishable_identity_refuses_the_placeholder_and_the_sandbox_but_not_the_operator() {
        const OP: &str = "A Person";
        const OP_MAIL: &str = "person@example.com";
        let jj = kata_types::commit_identity::JJ_EMPTY_IDENTITY_PLACEHOLDER;
        let sandbox_name = kata_types::commit_identity::SANDBOX_AGENT_NAME;
        let sandbox_mail = kata_types::commit_identity::SANDBOX_AGENT_EMAIL;

        let placeholder = require_publishable_identity("promote", "abc123", jj, jj, OP, OP_MAIL)
            .expect_err("must refuse a placeholder AUTHOR");
        assert!(placeholder.to_string().contains("abc123"), "{placeholder}");
        assert!(placeholder.to_string().contains("author"), "{placeholder}");
        assert!(
            placeholder.to_string().contains("Nothing was published"),
            "{placeholder}"
        );

        // The COMMITTER half: `git commit --amend` preserves the author, so a
        // rewritten commit reaches the refusal carrying the operator as author
        // and kata's sentinel as committer.
        let committer = require_publishable_identity(
            "forge_export",
            "abc123",
            OP,
            OP_MAIL,
            sandbox_name,
            sandbox_mail,
        )
        .expect_err("must refuse a sandbox COMMITTER even when the author is the operator");
        assert!(committer.to_string().contains("committer"), "{committer}");

        assert!(
            require_publishable_identity(
                "forge_export",
                "abc123",
                sandbox_name,
                sandbox_mail,
                OP,
                OP_MAIL,
            )
            .is_err()
        );

        assert_eq!(
            require_publishable_identity("promote", "abc123", OP, OP_MAIL, OP, OP_MAIL)
                .expect("operator identity is publishable"),
            "A Person <person@example.com>",
        );
    }

    #[test]
    fn observing_a_path_that_is_not_a_repository_yields_a_refusal_not_a_panic() {
        let observed = observe_identity_at(Path::new("/nonexistent/kata-identity-probe"));
        assert!(observed.git_author_ident.is_none());
        assert!(observed.git_refusal.is_some());
        assert!(resolve_commit_identity(&observed).is_err());
    }
}
