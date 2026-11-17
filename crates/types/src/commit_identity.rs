//! The identities KATA ITSELF can mint — and which of them may never reach a
//! commit that leaves the execution workspace.
//!
//! # The principle
//!
//! kata does not decide who is committing: it is a frontend for writing and
//! running Starlark workflows, and by default it uses git with whatever identity
//! and credentials the host it runs on already has.
//!
//! So kata INHERITS the host's answer to *who am I* and REFUSES when there
//! isn't one. It never invents an identity. Resolving the host's answer is
//! `kata_vcs::identity`; this module holds the small part that must be visible
//! to crates that do not depend on `kata-vcs` — `kata-types` itself carries the
//! receipt.
//!
//! # Three identities kata can mint, and none of them is a person
//!
//! 1. **jj's empty identity.** `jj_lib`'s `StackedConfig::with_defaults()` is
//!    exactly one layer — its built-in `config/misc.toml` — which sets
//!    `user.name = ""` and `user.email = ""`. `signature_to_git` substitutes
//!    [`JJ_EMPTY_IDENTITY_PLACEHOLDER`] for an empty field, because git refuses
//!    an empty ident. So the byte sequence a `git push` would carry to the
//!    operator's remote is `JJ_EMPTY_STRING <JJ_EMPTY_STRING>`. Measured
//!    against `jj 0.39.0` (the workspace's `jj-lib = "=0.39.0"` pin)
//!    with a `$HOME` holding only a `~/.gitconfig`: the jj side renders
//!    `AUTHOR=[] EMAIL=[]`, the git side renders
//!    `JJ_EMPTY_STRING <JJ_EMPTY_STRING>`.
//! 2. **The reserved agent-sandbox identity** ([`SANDBOX_AGENT_NAME`] /
//!    [`SANDBOX_AGENT_EMAIL`]). git's own "Please tell me who you are" refusal
//!    INSTRUCTS an agent with no identity to run `git config --global` — a
//!    measured probe had an agent do exactly that and produce a commit under a
//!    self-chosen plausible identity. Forwarding the OPERATOR's identity into a
//!    sandbox is the wrong fix: an agent stage is not the operator. This pair is
//!    a kata-owned, unmistakably-machine identity reserved for that seat, and the
//!    EFFECT path refuses it on sight, so a commit carrying it cannot survive a
//!    promote. No kata path stamps it into a sandbox today; the refusal stands
//!    on its own.
//! 3. **A fabricated placeholder** — a hard-coded `user.name`/`user.email`
//!    passed to `git -c`. Nothing in kata or its shipped packs spells one; a
//!    commit takes the host's identity or is refused, so there is no
//!    placeholder here to refuse.
//!
//! # What this module deliberately does NOT refuse
//!
//! [`kata_minted_identity_reason`] refuses exactly the identities KATA MINTS.
//! It does not judge the operator's: no TLD rule, no syntactic email check, no
//! allow-list. `test@example.invalid` — which `kata_test_utils`'s hermetic
//! fixtures declare — is a perfectly good answer to "who is committing in this
//! repository", and a rule keyed on RFC 2606 reserved domains would refuse it
//! along with every other deliberate placeholder an operator chose on purpose.
//! That would be kata deciding for people, which is the thing the principle
//! above forbids.

use serde::{Deserialize, Serialize};

/// What `jj_lib`'s `signature_to_git` writes into a git commit object when the
/// jj-side name or email is empty, because git refuses an empty ident field.
///
/// This is not an internal artifact: it is the literal byte sequence a
/// `git push` carries to the operator's remote.
pub const JJ_EMPTY_IDENTITY_PLACEHOLDER: &str = "JJ_EMPTY_STRING";

/// The `user.name` reserved for an AGENT SANDBOX.
///
/// Deliberately not a person and deliberately not plausible: its whole job is
/// to be recognised by [`kata_minted_identity_reason`] at every publish point,
/// so a commit carrying it cannot be parked, promoted or exported.
pub const SANDBOX_AGENT_NAME: &str = "kata sandbox agent";

/// The `user.email` reserved for an AGENT SANDBOX. `.invalid` is reserved by
/// RFC 2606 precisely so that it can never route anywhere.
pub const SANDBOX_AGENT_EMAIL: &str = "sandbox-agent@kata.invalid";

/// A commit author/committer identity, as the act that minted it recorded it.
///
/// Two fields and no timestamp: the timestamp belongs to the commit, and a
/// receipt that carried one would invite re-deriving the receipt from the
/// commit — which is exactly what makes it not a receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitIdentity {
    /// `user.name`.
    pub name: String,
    /// `user.email`.
    pub email: String,
}

impl CommitIdentity {
    /// Construct from an already-validated pair.
    #[must_use]
    pub fn new(name: impl Into<String>, email: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            email: email.into(),
        }
    }

    /// `Name <email>` — the same rendering `git log --format='%an <%ae>'`
    /// produces, so a recorded receipt and an operator's own read of the
    /// repository are string-comparable.
    #[must_use]
    pub fn author_line(&self) -> String {
        format!("{} <{}>", self.name, self.email)
    }

    /// [`kata_minted_identity_reason`] for this pair.
    #[must_use]
    pub fn minted_by_kata(&self) -> Option<&'static str> {
        kata_minted_identity_reason(&self.name, &self.email)
    }
}

/// Why this identity is one KATA minted rather than one the host stated, or
/// `None` when it is a usable operator identity.
///
/// THE ONE PLACE this classification lives. Every publish point (`commit`,
/// `park`, `promote`, `forge_export`) asks it, so "which identities may not
/// leave the execution workspace" cannot fork into four lists that drift.
///
/// The returned fragment is a sentence body — no leading capital, no trailing
/// period — so a refusal can splice it inline.
#[must_use]
pub fn kata_minted_identity_reason(name: &str, email: &str) -> Option<&'static str> {
    let name = name.trim();
    let email = email.trim();

    if name.is_empty() || email.is_empty() {
        return Some(
            "it is EMPTY — jj's built-in defaults are the only config layer kata loads, and they \
             set `user.name` and `user.email` to the empty string",
        );
    }
    if name == JJ_EMPTY_IDENTITY_PLACEHOLDER || email == JJ_EMPTY_IDENTITY_PLACEHOLDER {
        return Some(
            "it is jj's EMPTY-IDENTITY PLACEHOLDER (`JJ_EMPTY_STRING`), which is what an empty \
             jj identity renders as on the git side and what a `git push` would carry to the \
             operator's remote",
        );
    }
    if name == SANDBOX_AGENT_NAME || email == SANDBOX_AGENT_EMAIL {
        return Some(
            "it is the AGENT SANDBOX identity — a commit authored by an agent stage inside the \
             wrap, which is not the operator and whose work must be re-committed through a \
             `workspace_effect` stage before it can leave the execution workspace",
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_kata_minted_identities_are_all_refused() {
        assert!(kata_minted_identity_reason("", "").is_some());
        assert!(kata_minted_identity_reason("Someone", "").is_some());
        assert!(kata_minted_identity_reason("", "someone@example.test").is_some());
        assert!(
            kata_minted_identity_reason(
                JJ_EMPTY_IDENTITY_PLACEHOLDER,
                JJ_EMPTY_IDENTITY_PLACEHOLDER
            )
            .is_some()
        );
        assert!(kata_minted_identity_reason(SANDBOX_AGENT_NAME, SANDBOX_AGENT_EMAIL).is_some());
        assert!(
            CommitIdentity::new(SANDBOX_AGENT_NAME, SANDBOX_AGENT_EMAIL)
                .minted_by_kata()
                .is_some()
        );
    }

    #[test]
    fn an_operator_identity_is_not_refused_even_when_it_is_a_reserved_domain() {
        // `kata_test_utils::git::HERMETIC_OVERRIDES` declares exactly this pair,
        // and thousands of fixture commits carry it. A rule keyed on RFC 2606
        // reserved domains would refuse every one of them — and would be kata
        // deciding what a real identity looks like. kata refuses only the
        // identities it mints itself.
        assert_eq!(
            kata_minted_identity_reason("kata test", "test@example.invalid"),
            None
        );
        assert_eq!(
            kata_minted_identity_reason("A Person", "person@example.com"),
            None
        );
    }

    #[test]
    fn the_author_line_matches_gits_own_rendering() {
        let identity = CommitIdentity::new("A Person", "person@example.com");
        assert_eq!(identity.author_line(), "A Person <person@example.com>");
    }

    #[test]
    fn whitespace_only_fields_are_empty() {
        assert!(kata_minted_identity_reason("   ", "person@example.com").is_some());
        assert!(kata_minted_identity_reason("A Person", "\t").is_some());
    }
}
