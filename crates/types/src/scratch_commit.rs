//! The DURABLE record of one commit an agent wrote on its capsule's disposable
//! scratch branch — `ScratchCommitReport`.
//!
//! # Why this is a kata-types type and not a kata-worker one
//!
//! The commits are CREATED by the agent inside a scratch repository the worker
//! materialized (`kata-worker`'s `git_view` module lays out `/git`,
//! `/git-history` and the `/work/.git` gitfile), READ by the worker's
//! filesystem walk of the scratch gitdir after teardown confirms nothing in
//! the container still writes, and carried DURABLE inside the turn's Private
//! session-evidence blob — [`SessionEvidence::scratch_commits`] — which the
//! accepted completion's evidence row names. The type is shared rather than
//! worker-private because the serialized blob crosses the wire as one
//! artifact and is read back on the main that adopted it.
//!
//! # Why it rides `SessionEvidence`, not a wire field of its own
//!
//! A scratch-commit row is authored by the WORKER, not the session — the
//! adapter constructs `scratch_commits` empty because the record dies with
//! the session while the walk needs the container provably gone. But the
//! durable claim is identical to the events beside it: bounded, Private,
//! adopted with the completion, surfaced beside `model_reported` by the same
//! evidence row. A second field on `CompletedCapsule`, the adoption and
//! `ExecutionEvidence` would buy a parallel plumbing path for bytes the one
//! evidence blob already carries — so the worker fills the field between
//! `take_evidence` and serialize, and the wire frame never sees a report.
//!
//! # What a row deliberately is NOT
//!
//! It is EVIDENCE, not plumbing: the scratch repository is never adopted and
//! never lands on the host's repository — the durable record exists so a
//! review can read what the agent committed without trusting the agent's own
//! account. The commit ids are the scratch repo's own object ids, which are
//! meaningless outside the attempt (the objects die with it) except as names
//! for "this commit, distinct from that one".
//!
//! Every field is BOUNDED on the producer side: the list is capped at
//! `kata_worker::git_view`'s commit bound, `parents` at its parent bound, and
//! every text field first scrubbed against the attempt's lifted secret values
//! — an agent can write a commit message containing anything its vendor
//! process holds — then elided through
//! [`crate::redaction::elide`]'s one rule, so the blob stays small regardless
//! of what the guest wrote.

use serde::{Deserialize, Serialize};
use ulid::Ulid;

/// One commit the agent left on `refs/heads/kata/<execution-id>` — walked back
/// from the scratch branch tip to (and excluding) the base commit the capsule
/// declared, after the container's teardown confirmed nothing was still
/// writing.
///
/// `attempt_id` + `seq` is the dedupe coordinate, exactly as
/// [`EgressRefusalReport`](crate::egress_refusal::EgressRefusalReport)'s is:
/// the rows are written inside the accepting transaction, so they exist once
/// per accepted attempt — a superseded or refused attempt records none.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScratchCommitReport {
    /// The attempt whose scratch repository held this commit
    /// (`attempts.attempt_id`).
    pub attempt_id: Ulid,
    /// The commit's order within that attempt's walk, from zero at the branch
    /// tip — the walk's order, kept so a reader folds rows in the sequence the
    /// worker observed them.
    pub seq: u64,
    /// The commit's object id, in the scratch repository's hex spelling.
    pub commit: String,
    /// The commit's parents, hex, in the order the commit object names them —
    /// at most `kata_worker::git_view`'s parent bound; the remainder rides
    /// [`Self::parents_dropped`].
    pub parents: Vec<String>,
    /// Parents the bound cut — `0` on every commit a `parents` list reports
    /// whole. A merge the agent wrote past the bound records a COUNT rather
    /// than pretending the list was complete.
    pub parents_dropped: u32,
    /// `author`'s name field, elided to the producer's byte bound.
    pub author_name: String,
    /// `author`'s email field, elided likewise.
    pub author_email: String,
    /// `committer`'s name field, elided likewise.
    pub committer_name: String,
    /// `committer`'s email field, elided likewise.
    pub committer_email: String,
    /// The commit message's subject — the text up to the first blank line,
    /// newlines folded, elided to the producer's byte bound.
    pub subject: String,
    /// The commit message's body — everything after the subject's blank line,
    /// elided to the producer's byte bound.
    pub body: String,
}
