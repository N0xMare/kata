//! Native workflow/factory memory wire types.
//!
//! Kata-native workflows use these types through the API/SDK. Files under
//! `.kata/memory/` are projections or proposal inbox entries that serialize the
//! same shapes; they are not the authoritative state plane.

use serde::{Deserialize, Serialize};

pub const MEMORY_SCHEMA_VERSION: u32 = 1;

/// A memory object's place in the global ⊃ project ⊃ workflow hierarchy.
/// Self-describing: a Workflow scope carries its project, so the ancestor chain
/// is computable from the value alone.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "tier")]
pub enum MemoryScope {
    Global,
    Project { project: String },
    Workflow { project: String, workflow: String },
}

impl Default for MemoryScope {
    /// Data with no `scope` (rows/blobs) maps to `Global`.
    fn default() -> Self {
        Self::Global
    }
}

impl MemoryScope {
    /// The serde `tier` tag of each variant, shallowest first: the authorable
    /// scope TIERS (`memory_writeback(scope=)`, the DSL catalog's
    /// `memory_writeback_scope` domain). Concrete project/workflow keys are
    /// runtime context, never authored.
    pub const TIERS: &'static [&'static str] = &["global", "project", "workflow"];

    /// The visibility window when THIS scope is the reader's base scope: the
    /// scope itself plus every strict ancestor, ordered deepest→shallowest.
    ///
    /// `Workflow{p,w}` → `[Workflow{p,w}, Project{p}, Global]`;
    /// `Project{p}` → `[Project{p}, Global]`; `Global` → `[Global]`.
    ///
    /// This set is exactly `{self} ∪ {strict ancestors}` — never a sibling. A
    /// `Workflow{p,w1}` reader's window never contains `Workflow{p,w2}`, the
    /// cross-workflow isolation guarantee enforced wherever a caller supplies
    /// this window as [`MemoryObjectQuery::scope_window`]. Runtime threading of
    /// the per-execution window (computing the base scope at read time) is not
    /// wired: only tests exercise it, and unsupplied (`None`) windows keep the
    /// flat, unscoped behavior.
    ///
    /// [`MemoryObjectQuery::scope_window`]: (see `kata_core::store::MemoryObjectQuery`)
    #[must_use]
    pub fn ancestors_inclusive(&self) -> Vec<MemoryScope> {
        match self {
            Self::Global => vec![Self::Global],
            Self::Project { project } => vec![
                Self::Project {
                    project: project.clone(),
                },
                Self::Global,
            ],
            Self::Workflow { project, workflow } => vec![
                Self::Workflow {
                    project: project.clone(),
                    workflow: workflow.clone(),
                },
                Self::Project {
                    project: project.clone(),
                },
                Self::Global,
            ],
        }
    }

    /// Stable, **injective** key for the SQL `scope` filter column.
    ///
    /// `project`/`workflow` are arbitrary operator strings (unvalidated `String`s
    /// — they may contain ANY byte, including separators and control chars), so
    /// the encoding must not rely on a "safe" delimiter. It is therefore
    /// **length-prefixed**: each component is emitted as its byte length, a `:`,
    /// then the raw bytes. Decoding reads the length, then exactly that many
    /// bytes — so a `:`, `/`, or `\x1f` inside a component cannot forge another
    /// scope's key. This is injective for ALL inputs:
    /// `Workflow{"a","b\x1fc"}` → `workflow:1:a:3:b\x1fc` and
    /// `Workflow{"a\x1fb","c"}` → `workflow:3:a\x1fb:1:c` are distinct (an earlier
    /// `\x1f`-separated form collided these — fixed). `Global` is the literal
    /// `"global"`, unreachable from the length-prefixed tiers.
    #[must_use]
    pub fn canonical_key(&self) -> String {
        match self {
            Self::Global => "global".to_string(),
            Self::Project { project } => format!("project:{}:{project}", project.len()),
            Self::Workflow { project, workflow } => format!(
                "workflow:{}:{project}:{}:{workflow}",
                project.len(),
                workflow.len()
            ),
        }
    }

    /// Inverse of [`MemoryScope::canonical_key`]. Total over every value this
    /// type can produce — round-trips for ANY project/workflow string (the
    /// length prefix makes the component boundaries unambiguous). Returns `None`
    /// only for keys this encoder never emits (malformed input).
    #[must_use]
    pub fn parse_canonical_key(key: &str) -> Option<MemoryScope> {
        // Consume one `<len>:<bytes>` field, returning (field, remainder).
        fn take_len_prefixed(s: &str) -> Option<(&str, &str)> {
            let (len_str, after_len) = s.split_once(':')?;
            let len: usize = len_str.parse().ok()?;
            // `get` returns `None` if `len` falls outside bounds or off a UTF-8
            // boundary — both impossible for a key this type emitted, so a clean
            // round-trip always succeeds and tampered keys reject safely.
            let field = after_len.get(..len)?;
            let rest = after_len.get(len..)?;
            Some((field, rest))
        }
        if key == "global" {
            return Some(Self::Global);
        }
        if let Some(body) = key.strip_prefix("project:") {
            let (project, rest) = take_len_prefixed(body)?;
            if !rest.is_empty() {
                return None;
            }
            return Some(Self::Project {
                project: project.to_string(),
            });
        }
        if let Some(body) = key.strip_prefix("workflow:") {
            let (project, rest) = take_len_prefixed(body)?;
            let (workflow, rest) = take_len_prefixed(rest.strip_prefix(':')?)?;
            if !rest.is_empty() {
                return None;
            }
            return Some(Self::Workflow {
                project: project.to_string(),
                workflow: workflow.to_string(),
            });
        }
        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryObjectKind {
    Objective,
    Task,
    Scenario,
    ValidationCriterion,
    Decision,
    Finding,
    Claim,
    Artifact,
    Candidate,
    Risk,
    MemoryLink,
    /// A compaction summary object. Produced by the deterministic memory
    /// compactor when a namespace's live-object count exceeds its bound: the
    /// oldest overflow entries are folded into a single per-namespace `Summary`
    /// object and then evicted, so a long factory run keeps bounded per-namespace
    /// object growth while older context is still readable (the summary carries a
    /// digest of every folded entry). Never itself folded.
    Summary,
}

impl MemoryObjectKind {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Objective => "objective",
            Self::Task => "task",
            Self::Scenario => "scenario",
            Self::ValidationCriterion => "validation_criterion",
            Self::Decision => "decision",
            Self::Finding => "finding",
            Self::Claim => "claim",
            Self::Artifact => "artifact",
            Self::Candidate => "candidate",
            Self::Risk => "risk",
            Self::MemoryLink => "memory_link",
            Self::Summary => "summary",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "objective" => Some(Self::Objective),
            "task" => Some(Self::Task),
            "scenario" => Some(Self::Scenario),
            "validation_criterion" => Some(Self::ValidationCriterion),
            "decision" => Some(Self::Decision),
            "finding" => Some(Self::Finding),
            "claim" => Some(Self::Claim),
            "artifact" => Some(Self::Artifact),
            "candidate" => Some(Self::Candidate),
            "risk" => Some(Self::Risk),
            "memory_link" => Some(Self::MemoryLink),
            "summary" => Some(Self::Summary),
            _ => None,
        }
    }

    /// The closed set of kind spellings [`Self::parse`] accepts, in enum order —
    /// the one list an authoring error or a catalog domain reads so the parse
    /// domain and the spelled-out set cannot drift.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Objective,
            Self::Task,
            Self::Scenario,
            Self::ValidationCriterion,
            Self::Decision,
            Self::Finding,
            Self::Claim,
            Self::Artifact,
            Self::Candidate,
            Self::Risk,
            Self::MemoryLink,
            Self::Summary,
        ]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryObjectStatus {
    Proposed,
    Active,
    Superseded,
    Resolved,
    Rejected,
    Parked,
}

impl MemoryObjectStatus {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::Resolved => "resolved",
            Self::Rejected => "rejected",
            Self::Parked => "parked",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "proposed" => Some(Self::Proposed),
            "active" => Some(Self::Active),
            "superseded" => Some(Self::Superseded),
            "resolved" => Some(Self::Resolved),
            "rejected" => Some(Self::Rejected),
            "parked" => Some(Self::Parked),
            _ => None,
        }
    }

    /// The closed set of status spellings [`Self::parse`] accepts, in enum
    /// order — see [`MemoryObjectKind::all`].
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Proposed,
            Self::Active,
            Self::Superseded,
            Self::Resolved,
            Self::Rejected,
            Self::Parked,
        ]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemorySourceKind {
    Operator,
    Workflow,
    Worker,
    Sdk,
    ExternalFile,
    System,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryProvenance {
    pub source_kind: MemorySourceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryLinkRef {
    pub relation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MemoryObject {
    pub schema_version: u32,
    pub id: String,
    pub kind: MemoryObjectKind,
    pub status: MemoryObjectStatus,
    /// Place in the global ⊃ project ⊃ workflow hierarchy. Every stored object
    /// serializes it, so a blob without one is refused rather than defaulted.
    pub scope: MemoryScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default)]
    pub body: serde_json::Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<MemoryLinkRef>,
    pub provenance: MemoryProvenance,
    pub revision: u64,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MemoryObjectDraft {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub kind: MemoryObjectKind,
    #[serde(default = "default_memory_status")]
    pub status: MemoryObjectStatus,
    /// Declared scope for the promoted object. `#[serde(default)]` keeps a
    /// draft with no scope deserializing as `Global`.
    #[serde(default)]
    pub scope: MemoryScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default)]
    pub body: serde_json::Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<MemoryLinkRef>,
    pub provenance: MemoryProvenance,
}

fn default_memory_status() -> MemoryObjectStatus {
    MemoryObjectStatus::Proposed
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MemoryProposal {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_revision: Option<u64>,
    pub object: MemoryObjectDraft,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_file: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MemoryConflict {
    pub schema_version: u32,
    pub conflict_id: String,
    pub object_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_revision: Option<u64>,
    pub reason: String,
    pub proposal: MemoryProposal,
    pub recorded_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MemoryProposalResponse {
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<MemoryObject>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conflict: Option<MemoryConflict>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MemorySnapshot {
    pub schema_version: u32,
    pub generated_at_ms: u64,
    pub revision_head: u64,
    pub object_count: usize,
    pub objects: Vec<MemoryObject>,
}

#[cfg(test)]
mod scope_tier_tests {
    use super::MemoryScope;

    /// `TIERS` is the serde `tier` tag of every variant, shallowest first — read
    /// off the serializer.
    #[test]
    fn tiers_are_the_serde_tier_tags() {
        let tags: Vec<String> = [
            MemoryScope::Global,
            MemoryScope::Project {
                project: "p".to_owned(),
            },
            MemoryScope::Workflow {
                project: "p".to_owned(),
                workflow: "w".to_owned(),
            },
        ]
        .iter()
        .map(|scope| {
            serde_json::to_value(scope).expect("serializes")["tier"]
                .as_str()
                .expect("a tier tag")
                .to_owned()
        })
        .collect();
        assert_eq!(tags, MemoryScope::TIERS);
    }
}
