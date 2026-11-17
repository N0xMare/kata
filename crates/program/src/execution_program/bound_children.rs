//! The STORED form of a program's bound subworkflow children: each distinct child once.
//!
//! A subworkflow stage binds its child program at the parent's check
//! ([`super::SubworkflowBinder`]), and the child's own subworkflow stages bind theirs, so
//! one compile can bind the same child at many invocations. Stored nested — each
//! invocation carrying its own copy of the child's body — the program grew with the
//! number of INVOCATIONS: the review measured fan-out 3 at depth 6 as 1092 embedded
//! programs and 3.3 MB. Identity in this IR is content, so a child is its hash, and the
//! stored form says so:
//!
//! * a [`BoundChildProgram`] is stored as `{"program_hash": …}` alone;
//! * the program being stored carries ONE top-level `bound_children` table, mapping the
//!   hash of every distinct bound child reachable from it, at any depth, to that child's
//!   body — stored in its own field-by-field form, with its children again by hash and
//!   no table of its own (the one table is the closure).
//!
//! A program with no subworkflow stage has no table and stores byte-for-byte as before.
//!
//! # Decode
//!
//! Every reference is resolved against the table of the program being decoded, and each
//! distinct child is decoded ONCE and shared (`Arc`) by every reference to it. Refused,
//! each by name, so a stored program never decodes into a child its bytes do not bind:
//!
//! * `bound_child_unresolved` — a reference whose hash the table does not hold, or a
//!   reference decoded outside any program (a bare `SubworkflowSpec`);
//! * `bound_child_program_mismatch` — a table entry whose body does not re-derive the
//!   hash it is keyed under ([`BoundChildProgram::bind_shared`]);
//! * `bound_child_table_malformed` — an entry that carries a table of its own, an entry
//!   no reference reaches (bytes the program's hash does not bind), a reference cycle
//!   through the table, or a table that is not a map of hash to program;
//! * `subworkflow_depth_exceeded` — a bound child nesting deeper than
//!   [`super::MAX_SUBWORKFLOW_DEPTH`] invocations below the root of the program being
//!   decoded: the bound the compile refuses past, so the stored form cannot hold a tree
//!   the CHECK would never bind. A child is decoded once however many references share
//!   it, so every reference is judged — the one that decodes it and each later one —
//!   against that child's own height.
//!
//! The derived field-by-field form (`#[serde(remote = "Self")]` on
//! [`ExecutionProgram`]) is the ONE spelling of a program's fields; these impls only add
//! and resolve the table around it.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::sync::Arc;

use kata_types::primitives::ContentHash;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{BoundChildProgram, ExecutionProgram};

/// The stored name of the table.
const TABLE: &str = "bound_children";

impl ExecutionProgram {
    /// Every DISTINCT bound child reachable from this program's subworkflow stages, at any
    /// depth, keyed by its program hash's rendering (the stored key) — the stored table.
    fn bound_child_closure(&self) -> BTreeMap<String, &ExecutionProgram> {
        fn walk<'a>(
            program: &'a ExecutionProgram,
            into: &mut BTreeMap<String, &'a ExecutionProgram>,
        ) {
            for stage in program.stages.values() {
                let Some(spec) = stage.subworkflow.as_ref() else {
                    continue;
                };
                let key = spec.bound.program_hash().to_string();
                if into.contains_key(&key) {
                    continue;
                }
                into.insert(key, spec.bound.shared());
                walk(spec.bound.shared(), into);
            }
        }
        let mut closure = BTreeMap::new();
        walk(self, &mut closure);
        closure
    }

    /// Every DISTINCT bound child program reachable from this program's subworkflow
    /// stages, at any depth, each once — the programs a run of this one can spawn, since
    /// the runtime spawns exactly the bound bytes and re-resolves no pack name.
    ///
    /// The walk visits a child once per distinct hash, so it is linear in distinct
    /// children however many invocations share them, and it terminates on any value of
    /// this type: a [`BoundChildProgram`] holds its body by `Arc`, built child-first, so
    /// the reference graph is acyclic (a stored cycle is refused at decode,
    /// `bound_child_table_malformed`). Its recursion depth is the nesting depth, which a
    /// compile and the decode both bound at [`super::MAX_SUBWORKFLOW_DEPTH`]
    /// (`subworkflow_depth_exceeded`). It deliberately applies no depth cutoff of its own:
    /// a cutoff would hide a deeper child the runtime still spawns.
    pub fn bound_child_programs(&self) -> impl Iterator<Item = &ExecutionProgram> {
        self.bound_child_closure().into_values()
    }
}

/// A program in its field-by-field form, with no table of its own: a table entry, and
/// (flattened) the fields of the program the table is stored beside.
struct Entry<'a>(&'a ExecutionProgram);

impl Serialize for Entry<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ExecutionProgram::serialize(self.0, serializer)
    }
}

impl Serialize for ExecutionProgram {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let closure = self.bound_child_closure();
        if closure.is_empty() {
            return ExecutionProgram::serialize(self, serializer);
        }
        #[derive(Serialize)]
        struct Stored<'a> {
            #[serde(flatten)]
            program: Entry<'a>,
            bound_children: BTreeMap<String, Entry<'a>>,
        }
        Stored {
            program: Entry(self),
            bound_children: closure
                .into_iter()
                .map(|(hash, program)| (hash, Entry(program)))
                .collect(),
        }
        .serialize(serializer)
    }
}

/// The table of the program being decoded, and the children resolved from it so far.
struct Resolver {
    /// Entries not yet decoded, taken on first reference.
    pending: RefCell<BTreeMap<String, serde_json::Value>>,
    /// Entries decoded, shared by every later reference, each with its HEIGHT: how many
    /// invocations its deepest descendant sits below it (0: it invokes no subworkflow).
    decoded: RefCell<BTreeMap<String, (BoundChildProgram, usize)>>,
    /// Entries being decoded — a reference back to one is a cycle. They are the chain
    /// from the root to the reference being resolved, so a reference sits at depth
    /// `decoding.len() + 1` below the root.
    decoding: RefCell<BTreeSet<String>>,
}

thread_local! {
    /// The resolvers of the programs being decoded on this thread, innermost last. A
    /// stack rather than a slot so a program decoded while another is (a nested top-level
    /// decode) resolves against its own table.
    static RESOLVERS: RefCell<Vec<Rc<Resolver>>> = const { RefCell::new(Vec::new()) };
}

/// Pops the resolver it pushed on every exit, an error included.
struct Scope;

impl Scope {
    fn enter(resolver: Rc<Resolver>) -> Self {
        RESOLVERS.with(|stack| stack.borrow_mut().push(resolver));
        Self
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        RESOLVERS.with(|stack| stack.borrow_mut().pop());
    }
}

fn malformed<E: serde::de::Error>(detail: &str) -> E {
    E::custom(format!("bound_child_table_malformed: {detail}"))
}

/// Refuse a reference to bound child `hash` whose subtree reaches `deepest` invocations
/// below the root, when that is deeper than [`super::MAX_SUBWORKFLOW_DEPTH`].
fn refuse_too_deep<E: serde::de::Error>(hash: ContentHash, deepest: usize) -> Result<(), E> {
    if deepest <= super::MAX_SUBWORKFLOW_DEPTH {
        return Ok(());
    }
    Err(E::custom(format!(
        "subworkflow_depth_exceeded: the stored program nests bound child {hash}'s subtree to \
         depth {deepest} below its root; at most {max} nested subworkflow invocations below \
         the root are admitted, the bound its compile refuses past",
        max = super::MAX_SUBWORKFLOW_DEPTH,
    )))
}

fn resolve<E: serde::de::Error>(hash: ContentHash) -> Result<BoundChildProgram, E> {
    let resolver = RESOLVERS
        .with(|stack| stack.borrow().last().cloned())
        .ok_or_else(|| {
            E::custom(format!(
                "bound_child_unresolved: bound child {hash} is referenced outside the decode of \
                 a program, so there is no `{TABLE}` table to resolve it against"
            ))
        })?;
    let key = hash.to_string();
    let depth = resolver.decoding.borrow().len() + 1;
    if let Some((bound, height)) = resolver.decoded.borrow().get(&key) {
        refuse_too_deep(hash, depth + height)?;
        return Ok(bound.clone());
    }
    if resolver.decoding.borrow().contains(&key) {
        return Err(malformed(&format!(
            "bound child {hash} references itself through the table"
        )));
    }
    // Before the body is decoded, so a stored chain of any length stops here rather than
    // recursing through it.
    refuse_too_deep(hash, depth)?;
    let entry = resolver.pending.borrow_mut().remove(&key).ok_or_else(|| {
        E::custom(format!(
            "bound_child_unresolved: bound child {hash} is referenced and the program's \
             `{TABLE}` table holds no body for it"
        ))
    })?;
    if entry.get(TABLE).is_some() {
        return Err(malformed(&format!(
            "the entry for bound child {hash} carries a table of its own; the program's one \
             table is the closure"
        )));
    }
    resolver.decoding.borrow_mut().insert(key.clone());
    let program = ExecutionProgram::deserialize(entry).map_err(E::custom)?;
    resolver.decoding.borrow_mut().remove(&key);
    if program.program_hash != hash {
        return Err(E::custom(super::types::bound_child_mismatch(
            &program,
            hash,
            program.program_hash,
        )));
    }
    // Every child this body references was resolved while it decoded, so each has its
    // height recorded.
    let mut height = 0;
    for spec in program
        .stages
        .values()
        .filter_map(|stage| stage.subworkflow.as_ref())
    {
        let child = spec.bound.program_hash();
        let child_height = resolver
            .decoded
            .borrow()
            .get(&child.to_string())
            .map(|(_, child_height)| *child_height)
            .ok_or_else(|| {
                malformed::<E>(&format!(
                    "bound child {hash} references {child}, which its decode did not resolve"
                ))
            })?;
        height = height.max(child_height + 1);
    }
    let bound = BoundChildProgram::bind_shared(Arc::new(program)).map_err(E::custom)?;
    resolver
        .decoded
        .borrow_mut()
        .insert(key, (bound.clone(), height));
    Ok(bound)
}

impl<'de> Deserialize<'de> for ExecutionProgram {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut value = serde_json::Value::deserialize(deserializer)?;
        let table = match value
            .as_object_mut()
            .and_then(|fields| fields.remove(TABLE))
        {
            None => BTreeMap::new(),
            Some(table) => serde_json::from_value::<BTreeMap<String, serde_json::Value>>(table)
                .map_err(|error| malformed::<D::Error>(&error.to_string()))?,
        };
        let resolver = Rc::new(Resolver {
            pending: RefCell::new(table),
            decoded: RefCell::new(BTreeMap::new()),
            decoding: RefCell::new(BTreeSet::new()),
        });
        let program = {
            let _scope = Scope::enter(Rc::clone(&resolver));
            ExecutionProgram::deserialize(value).map_err(D::Error::custom)?
        };
        if let Some(unreached) = resolver.pending.borrow().keys().next() {
            return Err(malformed(&format!(
                "the entry for bound child {unreached} is reached by no reference, so the \
                 program's hash does not bind it"
            )));
        }
        Ok(program)
    }
}

impl Serialize for BoundChildProgram {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Stored {
            program_hash: ContentHash,
        }
        Stored {
            program_hash: self.program_hash(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BoundChildProgram {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Stored {
            program_hash: ContentHash,
        }
        resolve(Stored::deserialize(deserializer)?.program_hash)
    }
}
