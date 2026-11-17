//! Authoring-source coordinates: the `pack.star:LINE:COL` origin of a thing the
//! author wrote.
//!
//! Neutral core type, deliberately in `kata-types` rather than in the compiler:
//! it is carried by a workflow DEFINITION
//! ([`crate::workflow::StageDefinition::authored_span`]), by the checked IR, and
//! by verifier diagnostics, so it must not live behind the crate that only one
//! of those three belongs to.
//!
//! # `file` is a BASENAME, never a host path
//!
//! Locked authoring rule: a pack compiles to a content-hashed IR that may not
//! name a machine's facts, and an absolute path is exactly such a fact. Every
//! producer of a [`SourceSpan`] therefore reduces the source file to its
//! basename (`"pack.star"`) before constructing one. That is an invariant of the
//! type's meaning, not of any one producer: a reader may render a span into an
//! operator-facing diagnostic, into serialized IR, or into a hash without first
//! having to sanitize it.

use serde::{Deserialize, Serialize};

/// The `pack.star:LINE:COL` origin of an authored construct or a diagnostic.
///
/// `line`/`column` are 1-based (the human-facing convention, and what an editor
/// jumps to); `file` is the source BASENAME (e.g. `"pack.star"`), never a host
/// path — see the module preamble.
///
/// This is a coarse CALL-SITE span: the location of the builtin call that minted
/// the construct. It is NOT a template source-map — a `{{ ref }}` inside a prompt
/// string maps to the stage's call site, not to a byte offset inside the
/// template. True template source-maps are a later phase.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSpan {
    /// Source file basename (e.g. `"pack.star"`). Never a host path.
    pub file: String,
    /// 1-based line of the span's start.
    pub line: u32,
    /// 1-based column of the span's start.
    pub column: u32,
}

impl std::fmt::Display for SourceSpan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}:{}", self.file, self.line, self.column)
    }
}
