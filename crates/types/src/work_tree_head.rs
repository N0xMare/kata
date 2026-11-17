//! WHERE inside one execution a `/work` head sits: the stack of `parallel()`
//! branches enclosing it, outermost first.

use crate::error::{KataError, KataResult};

/// WHICH `parallel()` fork a head row belongs to: the barrier stage and the
/// branch's exit stage (the join's `depends_on` member closing the branch).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchFork {
    /// The barrier stage's id.
    pub join: String,
    /// The branch's exit stage — the join input this head answers for.
    pub exit: String,
}

/// WHERE inside one execution a `/work` head sits: the stack of `parallel()`
/// branches enclosing it, outermost first. `[]` is the execution's own head —
/// the root coordinate, spelled `''`.
///
/// The branch-head model: every stage of a checked program answers one coordinate —
/// its own enclosing-branch stack — and a capsule's `/work` maps the head row
/// at exactly it. A `parallel()` barrier's join computes each input's delta
/// against the branch row's frozen `fork_base_artifact_id`, merges them with
/// `TreeDelta::merge`, and applies the union to the head row at the BARRIER's
/// own coordinate — so a nested barrier composes through the same rule, one
/// level at a time.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WorkTreeHeadCoordinate(Vec<BranchFork>);

impl WorkTreeHeadCoordinate {
    /// The execution's own head — equivalently `Self::default()` (the empty
    /// fork stack is the root coordinate; keep `root()` for the name).
    pub fn root() -> Self {
        Self(Vec::new())
    }

    /// The coordinate one fork deeper: the branch of barrier `join` whose exit
    /// stage is `exit`, inside this coordinate's branch.
    #[must_use]
    pub fn pushed(&self, join: impl Into<String>, exit: impl Into<String>) -> Self {
        let mut forks = self.0.clone();
        forks.push(BranchFork {
            join: join.into(),
            exit: exit.into(),
        });
        Self(forks)
    }

    /// The enclosing coordinate — the parent head this coordinate's row was
    /// forked from — or `None` at the root.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        let mut forks = self.0.clone();
        forks.pop().map(|_| Self(forks))
    }

    /// The INNERMOST fork, when this coordinate is a branch at all.
    #[must_use]
    pub fn innermost(&self) -> Option<&BranchFork> {
        self.0.last()
    }

    /// Whether this is the execution's own head.
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// The stored spelling: `''` at the root, else canonical JSON — a list of
    /// `[join, exit]` pairs, outermost first. JSON rather than a joined path
    /// string because a stage id may carry any character the author chose.
    #[must_use]
    pub fn spelling(&self) -> String {
        if self.0.is_empty() {
            return String::new();
        }
        let pairs: Vec<[&str; 2]> = self
            .0
            .iter()
            .map(|fork| [fork.join.as_str(), fork.exit.as_str()])
            .collect();
        serde_json::to_string(&pairs)
            .expect("a coordinate's spelling is a JSON string list — serialization cannot fail")
    }

    /// Decode a stored spelling back, or refuse the one thing it may not be.
    ///
    /// # Errors
    ///
    /// `Validation` when `stored` is not the canonical spelling of a
    /// coordinate — a hand-edited row, which this plane refuses rather than
    /// reinterprets.
    pub fn from_spelling(stored: &str) -> KataResult<Self> {
        if stored.is_empty() {
            return Ok(Self::root());
        }
        let pairs: Vec<[String; 2]> = serde_json::from_str(stored).map_err(|error| {
            KataError::Validation(format!(
                "work tree head coordinate {stored:?} is not the canonical spelling: {error}"
            ))
        })?;
        let mut coordinate = Self::root();
        for [join, exit] in pairs {
            coordinate = coordinate.pushed(join, exit);
        }
        // Round-trip so a spelling this build would not mint — unpaired forks,
        // non-canonical JSON — cannot ride in.
        if coordinate.spelling() != stored {
            return Err(KataError::Validation(format!(
                "work tree head coordinate {stored:?} is not in canonical form"
            )));
        }
        Ok(coordinate)
    }
}
