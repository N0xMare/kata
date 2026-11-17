//! Validation concern: load-time contract type-check, branch-route
//! exhaustiveness, and arm-disjointness checks over the registered graph.
//!
//! Concern-split out of `dsl/builder.rs` (behavior-preserving move).

use super::{BranchNode, StageNode, discriminant_tags, produces_contract_field};

/// The load-time contract type-checker.
///
/// For every stage `B` that declares a `consumes=` contract, this verifies that
/// at least one of `B`'s `depends_on` upstreams declares a `produces=` contract
/// whose generated schema is a **subtype** of `B`'s `consumes` schema
/// (`crate::dsl::schema::is_subtype`), i.e. a producer that always delivers what the
/// consumer reads.
///
/// # Compatibility rule (v2, width+depth subtyping)
///
/// * Matching is **structural SUBTYPING**, not equality: a producer schema
///   satisfies a consumer schema when it is a `crate::dsl::schema::is_subtype` of it.
///   This is strictly more permissive than the original `serde_json::Value`
///   equality — a SUPERSET producer (extra fields) satisfies a SUBSET consumer
///   (WIDTH); a per-field/element/tag DEPTH check recurses; an enum/variant
///   producer whose tag set is a SUBSET of the consumer's is accepted; `integer`
///   satisfies `number`. It is soundness-critical: it NEVER accepts an
///   incompatible contract (the soundness directions are documented on
///   `is_subtype`). The contract *name* is used only for diagnostics, not for
///   matching — a `produces` and a `consumes` of differently-named but
///   subtype-compatible contracts are compatible.
/// * **Multi-`depends_on`:** `B`'s `consumes` must match the `produces` of
///   *exactly one viable upstream* — i.e. at least one upstream of `B` produces a
///   matching contract. Upstreams that declare no `produces=` are simply ignored
///   (they contribute no contract to satisfy `B`'s consumes; this is legal). It
///   is an error if *none* of `B`'s upstreams produce a matching contract.
/// * A `consumes=` with no `depends_on` upstream that produces *anything*
///   matching is an error ("consumes `X` but no upstream produces it").
/// * A stage with no `consumes=` is unchecked: the check is opt-in. Programmatic
///   checked definitions do not reach this Starlark authoring-boundary check.
///
/// The check is pure and deterministic: it reads only the registered stage set
/// and iterates it in registration order, performing no I/O.
pub(crate) fn check_contracts(stages: &[StageNode]) -> Result<(), String> {
    for stage in stages {
        let Some(consumes_schema) = stage.consumes_schema.as_ref() else {
            continue;
        };
        let consumes_name = stage.consumes_name.as_deref().unwrap_or("<unnamed>");

        // Collect this stage's upstreams that declare a `produces=` contract, in
        // author-declared `depends_on` order, paired with their producer stage.
        let mut producing_upstreams: Vec<&StageNode> = Vec::new();
        for dep_id in &stage.depends_on {
            if let Some(up) = stages.iter().find(|s| &s.id == dep_id)
                && up.produces_schema.is_some()
            {
                producing_upstreams.push(up);
            }
        }

        // Width+depth structural SUBTYPING (was strict `Value` equality).
        // `B`'s `consumes` is satisfied iff SOME viable upstream's `produces`
        // schema is a SUBTYPE of it — i.e. a superset producer satisfies a subset
        // consumer, an enum/variant producer emitting a SUBSET of the consumer's
        // tags is accepted, etc. `is_subtype` is soundness-critical (never a
        // false-accept): see `crate::dsl::schema::is_subtype`.
        let matched = producing_upstreams.iter().any(|up| {
            up.produces_schema
                .as_ref()
                .is_some_and(|produces| crate::dsl::schema::is_subtype(produces, consumes_schema))
        });

        if !matched {
            if producing_upstreams.is_empty() {
                return Err(format!(
                    "stage {stage_id:?} consumes contract `{consumes_name}` but no upstream \
                     produces it: none of its depends_on stages declare a produces= contract",
                    stage_id = stage.id,
                ));
            }
            let produced: Vec<String> = producing_upstreams
                .iter()
                .map(|up| {
                    format!(
                        "{up_id:?} produces `{name}`",
                        up_id = up.id,
                        name = up.produces_name.as_deref().unwrap_or("<unnamed>"),
                    )
                })
                .collect();
            return Err(format!(
                "stage {stage_id:?} consumes contract `{consumes_name}` but no upstream produces \
                 a matching contract; upstream producers: [{produced}]",
                stage_id = stage.id,
                produced = produced.join(", "),
            ));
        }
    }
    Ok(())
}

/// The load-time branch exhaustiveness type-checker.
///
/// For every recorded `branch(..)` route, this verifies the typed-branch
/// guarantee: the condition stage MUST declare a `produces=contract(..)` whose
/// field named `verdict_field` is a `variant(..)`, and the branch arms' tag set
/// MUST EXACTLY equal that variant's tag set — every variant tag has an arm AND
/// no arm names a non-existent tag. Otherwise the workflow FAILS TO COMPILE here
/// (a clear both-sides error listing the missing and/or extra tags).
///
/// The condition-stage existence, arm-target existence, and verdict_field
/// presence were already checked at `branch()` registration ([`register_branch`])
/// for a per-call error; this drain-time pass is where the *variant-ness* and
/// *tag exhaustiveness* are decided against the fully-registered stage set.
///
/// The check is pure and deterministic: it reads only the registered stage set
/// and branch list, performing no I/O.
pub(crate) fn check_branch_routes(
    stages: &[StageNode],
    branches: &[BranchNode],
) -> Result<(), String> {
    for branch in branches {
        let condition = stages
            .iter()
            .find(|s| s.id == branch.condition_id)
            .ok_or_else(|| {
                format!(
                    "branch() on= references unknown stage {:?}",
                    branch.condition_id
                )
            })?;
        let produces_schema = condition.produces_schema.as_ref().ok_or_else(|| {
            format!(
                "branch() condition stage {:?} must declare produces=contract(..) carrying a \
                 variant(..) field named {:?}; it declares no produces= contract",
                branch.condition_id, branch.verdict_field
            )
        })?;
        let field_schema = produces_contract_field(produces_schema, &branch.verdict_field)
            .ok_or_else(|| {
                format!(
                    "branch() verdict_field {:?} is not a field of condition stage {:?}'s \
                     produces= contract",
                    branch.verdict_field, branch.condition_id
                )
            })?;
        // The branch gate now accepts a `variant(..)` OR a string
        // `enum(..)` discriminant (the generalized `discriminant_tags`), so a
        // `route()`/`when()`/`branch_if()` (and a raw `branch()`) can route on a
        // typed enum verdict, not only a discriminated union. The exhaustiveness
        // + disjointness cores below are unchanged.
        let variant_tags = discriminant_tags(field_schema)
            .map(|info| info.tags)
            .ok_or_else(|| {
                format!(
                    "branch() verdict_field {:?} on condition stage {:?} must be a variant(..) or \
                     a string enum(..) field; a branch routes only on a typed discriminant",
                    branch.verdict_field, branch.condition_id
                )
            })?;

        // Exhaustiveness: the arm tag set must EXACTLY equal the variant tag set.
        let arm_tags: std::collections::BTreeSet<&str> =
            branch.arms.iter().map(|(tag, _)| tag.as_str()).collect();
        if let Some(detail) = branch_tag_exhaustiveness_detail(&arm_tags, &variant_tags) {
            return Err(format!(
                "branch() on condition stage {cond:?} is not exhaustive over verdict_field \
                 {field:?}: {detail}. variant declares tags [{variant}]; branch declares arms \
                 [{arms}]",
                cond = branch.condition_id,
                field = branch.verdict_field,
                variant = variant_tags.join(", "),
                arms = arm_tags.iter().copied().collect::<Vec<_>>().join(", "),
            ));
        }

        // The settled design fork for typed branches is
        // NO REJOINS — arms must be disjoint. Enforce it at COMPILE so the silent
        // runtime drop (a transitive rejoin descendant of the taken arm getting
        // Skipped by the non-taken arm's `skip_dependents` cascade) becomes a clean
        // load-time error. For each arm, compute the forward closure (transitive
        // descendants via the `depends_on` graph) of its targets; if any stage
        // appears in two or more arms' closures, the arms are NOT disjoint.
        check_branch_arms_disjoint(stages, branch)?;
    }
    Ok(())
}

/// Reject a branch whose arms are not disjoint.
///
/// "No rejoins" is a settled design constraint. A rejoin is a
/// stage reachable from MORE THAN ONE arm — directly (a stage that depends on a
/// target of two arms) or transitively (a descendant of two arms' subtrees). At
/// runtime the non-taken arm's `skip_dependents` cascade would silently Skip such
/// a stage even though it is reachable from the COMPLETED taken arm. This check
/// turns that silent loss into a clear compile error naming the rejoin stage and
/// the two offending arms.
///
/// For each arm, the closure is the set of stages reachable forward from the arm's
/// targets through the `depends_on` graph (a stage `X` is a descendant of seed `S`
/// when `X` transitively `depends_on` `S`). The arm targets themselves are seeds,
/// so a *direct* rejoin (one stage depending on a target of each of two arms) is
/// caught as the depended-on targets' shared descendant. The shared condition
/// stage is never in any closure: closures start at the arm targets and only walk
/// forward, never backward to the condition.
fn check_branch_arms_disjoint(stages: &[StageNode], branch: &BranchNode) -> Result<(), String> {
    // Forward adjacency: for each `X depends_on D` edge, record `D -> X` so a BFS
    // from an arm's targets walks to its descendants.
    let mut forward: std::collections::HashMap<&str, Vec<&str>> = std::collections::HashMap::new();
    for stage in stages {
        for dep in &stage.depends_on {
            forward
                .entry(dep.as_str())
                .or_default()
                .push(stage.id.as_str());
        }
    }

    // Compare every arm pair; report the first rejoin deterministically (arms are
    // in author order; the shared stage is the BTreeSet minimum so the message is
    // stable regardless of HashSet iteration order).
    let arms: Vec<(&str, Vec<String>)> = branch
        .arms
        .iter()
        .map(|(tag, targets)| (tag.as_str(), targets.clone()))
        .collect();
    if let Some((tag_a, tag_b, rejoin)) = first_branch_arm_rejoin(&forward, &arms) {
        return Err(format!(
            "branch() on condition stage {cond:?} arm {tag_a:?} and arm {tag_b:?} both \
             reach stage {rejoin:?}; branch arms must be disjoint (rejoins are not \
             supported)",
            cond = branch.condition_id,
        ));
    }
    Ok(())
}

/// The byte-identical branch exhaustiveness core used by the Starlark-drain
/// ([`check_branch_routes`]).
///
/// Given a branch's arm tag set and its condition variant's declared tags,
/// returns `None` when the arms EXACTLY cover the variant (exhaustive), else
/// `Some(detail)` where `detail` is the `"; "`-joined
/// `"missing arms for variant tags [..]"` / `"arms name non-existent tags [..]"`
/// fragment the callers embed verbatim in their (differently-prefixed) errors.
pub(crate) fn branch_tag_exhaustiveness_detail(
    arm_tags: &std::collections::BTreeSet<&str>,
    variant_tags: &[String],
) -> Option<String> {
    let variant_tag_set: std::collections::BTreeSet<&str> =
        variant_tags.iter().map(String::as_str).collect();
    let missing: Vec<&str> = variant_tag_set.difference(arm_tags).copied().collect();
    let extra: Vec<&str> = arm_tags.difference(&variant_tag_set).copied().collect();
    if missing.is_empty() && extra.is_empty() {
        return None;
    }
    let mut detail = Vec::new();
    if !missing.is_empty() {
        detail.push(format!(
            "missing arms for variant tags [{}]",
            missing.join(", ")
        ));
    }
    if !extra.is_empty() {
        detail.push(format!(
            "arms name non-existent tags [{}]",
            extra.join(", ")
        ));
    }
    Some(detail.join("; "))
}

/// The byte-identical "no rejoins" disjointness core used by the Starlark-drain
/// ([`check_branch_arms_disjoint`]).
///
/// `forward` is the `dep -> dependents` adjacency; each arm is `(tag, seed stage
/// ids)`. Returns the first rejoin — a stage forward-reachable from two arms — as
/// `(tag_a, tag_b, rejoin)`, comparing arms in author order and reporting
/// the lexicographically-smallest shared stage (BTreeSet minimum) so the result
/// is deterministic regardless of `HashSet` iteration order. The two callers
/// build `forward`/seeds from their own graph shapes and format their own error
/// around this result.
pub(crate) fn first_branch_arm_rejoin<'t>(
    forward: &std::collections::HashMap<&str, Vec<&str>>,
    arms: &[(&'t str, Vec<String>)],
) -> Option<(&'t str, &'t str, String)> {
    // closure(seeds) = seeds ∪ all forward-reachable descendants.
    let closure_of = |seeds: &[String]| -> std::collections::HashSet<String> {
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut stack: Vec<&str> = Vec::new();
        for seed in seeds {
            if seen.insert(seed.clone()) {
                stack.push(seed.as_str());
            }
        }
        while let Some(node) = stack.pop() {
            if let Some(children) = forward.get(node) {
                for child in children {
                    if seen.insert((*child).to_owned()) {
                        stack.push(child);
                    }
                }
            }
        }
        seen
    };

    let closures: Vec<(&str, std::collections::HashSet<String>)> = arms
        .iter()
        .map(|(tag, targets)| (*tag, closure_of(targets)))
        .collect();
    for (i, (tag_a, closure_a)) in closures.iter().enumerate() {
        for (tag_b, closure_b) in &closures[i + 1..] {
            let shared: std::collections::BTreeSet<&str> = closure_a
                .iter()
                .filter(|stage| closure_b.contains(*stage))
                .map(String::as_str)
                .collect();
            if let Some(rejoin) = shared.into_iter().next() {
                return Some((*tag_a, *tag_b, rejoin.to_owned()));
            }
        }
    }
    None
}
