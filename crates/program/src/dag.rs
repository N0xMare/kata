//! DAG construction, cycle detection, and topological ordering.
//!
//! Builds a directed acyclic graph from workflow stage definitions using
//! edges (explicit `StageEdge` entries) and implicit `depends_on` within
//! `StageInput` references. Cycle detection uses Kahn's algorithm.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use indexmap::IndexMap;
use kata_types::KataError;
use kata_types::workflow::{StageDefinition, StageEdge, StageId};
use smol_str::SmolStr;

/// A node in the workflow DAG.
#[derive(Clone, Debug)]
pub struct DagNode {
    pub name: SmolStr,
    pub depends_on: Vec<SmolStr>,
}

/// The workflow's directed acyclic graph with a precomputed topological order.
#[derive(Clone, Debug)]
pub struct WorkflowDag {
    nodes: IndexMap<SmolStr, DagNode>,
    topo_order: Vec<SmolStr>,
}

impl WorkflowDag {
    /// Build a `WorkflowDag` from stage definitions and explicit edges.
    ///
    /// Dependencies are derived from two sources:
    /// 1. `StageInput::from` fields (each input references a predecessor stage).
    /// 2. Explicit `StageEdge` entries.
    ///
    /// Returns an error if the graph contains a cycle or references
    /// non-existent stages.
    pub fn build(
        stages: &BTreeMap<StageId, StageDefinition>,
        edges: &[StageEdge],
    ) -> Result<Self, KataError> {
        let mut nodes: IndexMap<SmolStr, DagNode> = IndexMap::new();

        // Initialize all nodes from stages.
        for StageId(name) in stages.keys() {
            nodes.insert(
                name.clone(),
                DagNode {
                    name: name.clone(),
                    depends_on: Vec::new(),
                },
            );
        }

        // Collect dependencies from StageInput::from references.
        // First pass: validate all dependency refs exist.
        for (StageId(name), stage) in stages {
            for input in &stage.inputs {
                let dep = &input.from.0;
                if !nodes.contains_key(dep.as_str()) {
                    return Err(KataError::Validation(format!(
                        "stage \"{name}\" references non-existent dependency \"{dep}\" via input"
                    )));
                }
            }
        }
        // Second pass: insert dependencies.
        for (StageId(name), stage) in stages {
            let node = nodes.get_mut(name).expect("node was just inserted above");
            for input in &stage.inputs {
                let dep = &input.from.0;
                if !node.depends_on.contains(dep) {
                    node.depends_on.push(dep.clone());
                }
            }
        }

        // Collect dependencies from explicit edges.
        for edge in edges {
            let from = &edge.from.0;
            let to = &edge.to.0;
            if !nodes.contains_key(from.as_str()) {
                return Err(KataError::Validation(format!(
                    "edge references non-existent stage \"{from}\""
                )));
            }
            if !nodes.contains_key(to.as_str()) {
                return Err(KataError::Validation(format!(
                    "edge references non-existent stage \"{to}\""
                )));
            }
            // Edge means `to` depends on `from`.
            let node = nodes.get_mut(to.as_str()).unwrap();
            if !node.depends_on.contains(from) {
                node.depends_on.push(from.clone());
            }
        }

        // Kahn's algorithm for topological sort and cycle detection.
        let topo_order = kahns_sort(&nodes)?;

        Ok(Self { nodes, topo_order })
    }

    /// Build a `WorkflowDag` from a simple name-to-deps mapping.
    ///
    /// Convenience constructor for testing or programmatic DAG construction
    /// without full `StageDefinition`s.
    pub fn build_from_deps(deps: &IndexMap<SmolStr, Vec<SmolStr>>) -> Result<Self, KataError> {
        let mut nodes: IndexMap<SmolStr, DagNode> = IndexMap::new();

        for (name, dep_list) in deps {
            nodes.insert(
                name.clone(),
                DagNode {
                    name: name.clone(),
                    depends_on: dep_list.clone(),
                },
            );
        }

        // Validate all dependency references.
        for (name, node) in &nodes {
            for dep in &node.depends_on {
                if !nodes.contains_key(dep.as_str()) {
                    return Err(KataError::Validation(format!(
                        "stage \"{name}\" references non-existent dependency \"{dep}\""
                    )));
                }
            }
        }

        let topo_order = kahns_sort(&nodes)?;
        Ok(Self { nodes, topo_order })
    }

    /// Return the topological ordering of stage names.
    pub fn topological_order(&self) -> &[SmolStr] {
        &self.topo_order
    }

    /// Return the names of stages that are ready to execute.
    ///
    /// A stage is ready when all its dependencies are in the `completed` set
    /// and the stage itself is not yet completed.
    pub fn ready_stages(&self, completed: &HashSet<SmolStr>) -> Vec<SmolStr> {
        self.nodes
            .iter()
            .filter(|(name, node)| {
                !completed.contains(name.as_str())
                    && node
                        .depends_on
                        .iter()
                        .all(|dep| completed.contains(dep.as_str()))
            })
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Get the dependencies of a specific stage.
    pub fn dependencies(&self, stage: &str) -> Option<&[SmolStr]> {
        self.nodes.get(stage).map(|n| n.depends_on.as_slice())
    }

    /// Total number of stages.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the DAG contains no stages.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

/// Kahn's algorithm: topological sort with cycle detection.
fn kahns_sort(nodes: &IndexMap<SmolStr, DagNode>) -> Result<Vec<SmolStr>, KataError> {
    // Compute in-degree for each node. A node's in-degree equals the number
    // of dependencies it has (each dependency represents an incoming edge).
    let mut in_deg: HashMap<&str, usize> = HashMap::new();
    for (name, node) in nodes {
        in_deg.insert(name.as_str(), node.depends_on.len());
    }

    // Seed the queue with all nodes that have zero in-degree.
    let mut queue: VecDeque<&str> = VecDeque::new();
    for (name, &deg) in &in_deg {
        if deg == 0 {
            queue.push_back(name);
        }
    }

    // Build a forward adjacency list (from -> [to]) so we can decrement
    // successors' in-degrees when a node is "removed".
    let mut successors: HashMap<&str, Vec<&str>> = HashMap::new();
    for (name, node) in nodes {
        for dep in &node.depends_on {
            successors
                .entry(dep.as_str())
                .or_default()
                .push(name.as_str());
        }
    }

    let mut order: Vec<SmolStr> = Vec::with_capacity(nodes.len());
    while let Some(current) = queue.pop_front() {
        order.push(SmolStr::new(current));
        if let Some(succs) = successors.get(current) {
            for &succ in succs {
                let deg = in_deg.get_mut(succ).unwrap();
                *deg -= 1;
                if *deg == 0 {
                    queue.push_back(succ);
                }
            }
        }
    }

    if order.len() != nodes.len() {
        return Err(KataError::Validation(
            "workflow DAG contains a cycle".into(),
        ));
    }

    Ok(order)
}
