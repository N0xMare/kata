//! Machine-readable catalog of the native Starlark workflow DSL surface.
//!
//! An agent author should be able to *target* a schema instead of
//! reverse-engineering the DSL from examples. This module reflects the typed
//! builtin signatures — the `#[starlark_module]` families
//! [`super::kata_graph_globals`] (`stage` / `workflow` / `loop` / `branch` /
//! `parallel` / …) and [`super::kata_contract_globals`] (`contract` / `field` /
//! `enum` / `list_of` / `variant` / `number` / `integer` / `string` / …) — into
//! a stable, deterministic JSON catalog.
//!
//! # Fail-closed against schema drift
//!
//! The catalog is derived from the same [`starlark::environment::Globals`] the
//! evaluator wires in, via [`Globals::documentation`]. A newly-registered
//! builtin therefore appears in the catalog automatically with its kwargs,
//! types, defaults, and docstring — there is no hand-maintained second list to
//! drift out of sync. The crate test asserts the catalog covers *every*
//! registered builtin, so a builtin that somehow escaped documentation fails the
//! build rather than shipping an incomplete catalog.
//!
//! # Determinism
//!
//! [`Globals::documentation`] returns members sorted by name; each builtin's
//! parameters are emitted in signature order (positional-only, then
//! positional-or-named, then `*args`, then named-only, then `**kwargs`). The
//! catalog is a pure function of the registered builtins, so identical inputs
//! render byte-identical JSON.

use kata_types::agent_run;
use kata_types::cache::CachePolicy;
use kata_types::execution_class::{
    DECLARABLE_CONTAINMENT, DECLARABLE_DETERMINISM, DECLARABLE_NETWORK,
};
use kata_types::review_loop::OnMaxAction;
use kata_types::sandbox::NetPolicy;
use kata_types::workflow::{
    MutationPolicy, ProgressVisibility, ShellExitPolicy, WorkspaceEffectOp,
};

use crate::policy::HumanRequestPriority;
use crate::schedule::MissedPolicy;
use serde::Serialize;
use starlark::docs::{DocItem, DocMember, DocParam, DocParams};
use starlark::environment::GlobalsBuilder;

use super::schema::DEFAULT_LIST_MAX_ITEMS;
use super::{kata_contract_globals, kata_graph_globals};

/// Catalog schema version. Bump on a breaking change to the emitted JSON shape
/// (field renames/removals); additive fields do not require a bump.
pub const DSL_CATALOG_VERSION: u32 = 1;

/// The full machine-readable DSL catalog: every registered builtin plus the
/// contract grammar and decision-tag/verdict vocabulary an author needs to
/// write a workflow.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DslCatalog {
    /// Schema version of this catalog document ([`DSL_CATALOG_VERSION`]).
    pub version: u32,
    /// Every registered DSL builtin, sorted by name (deterministic).
    pub builtins: Vec<DslBuiltin>,
    /// The contract grammar + decision-tag vocabulary that the scalar builtin
    /// signatures alone do not capture.
    pub grammar: DslGrammar,
    /// The closed ENUM DOMAINS an author may spell for a string-valued kwarg
    /// (`cache_policy=`, `progress_visibility=`, `on_exhaustion=`,
    /// `topology(mutation_policy=)`, `stage(op=)`, ...), each reflected from the
    /// typed authority the builtin parses through — never a hand-copied list.
    /// Every closed string kwarg of the registered builtins has one, and so does
    /// each string key of `stage(execution_requirements={..})`
    /// (`execution_requirements_containment`, `_network`, `_determinism`).
    /// Sorted by domain name for determinism.
    pub enum_domains: Vec<DslEnumDomain>,
    /// The structured-output schema LIMITS the agent-run validator enforces,
    /// published from the single `kata_types::agent_run` authority so an author
    /// can target the exact bounds a contract must satisfy.
    pub limits: DslLimits,
}

/// One closed enum domain: the accepted `snake_case` spellings for a
/// string-valued DSL kwarg, reflected from a typed authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DslEnumDomain {
    /// The kwarg the domain governs (e.g. `"cache_policy"`).
    pub name: String,
    /// The accepted spellings, in the authority's declared order.
    pub values: Vec<String>,
}

/// The structured-output schema bounds an authored contract must satisfy, each
/// mirrored from the corresponding `kata_types::agent_run` authority const.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DslLimits {
    /// Maximum `output_schema` nesting depth
    /// ([`agent_run::MAX_SCHEMA_DEPTH`]).
    pub max_schema_depth: usize,
    /// Maximum object `properties` count ([`agent_run::MAX_SCHEMA_PROPERTIES`]).
    pub max_schema_properties: usize,
    /// Maximum object `required` count ([`agent_run::MAX_SCHEMA_REQUIRED`]).
    pub max_schema_required: usize,
    /// Maximum `list_of(..)`/array `maxItems` ([`agent_run::MAX_ARRAY_ITEMS`]).
    pub max_array_items: u64,
    /// Maximum string `minLength`/`maxLength` ([`agent_run::MAX_STRING_LENGTH`]).
    pub max_string_length: u64,
    /// Maximum `enum`/`variant` arm count ([`agent_run::MAX_ENUM_VARIANTS`]).
    pub max_enum_variants: usize,
    /// Maximum `allowed_tools` entry count ([`agent_run::MAX_ALLOWED_TOOLS`]).
    pub max_allowed_tools: usize,
    /// Maximum `allowed_tools` entry byte length
    /// ([`agent_run::MAX_TOOL_NAME_LEN`]).
    pub max_tool_name_len: usize,
}

/// One registered DSL builtin (a `#[starlark_module]` function such as `stage`
/// or `contract`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DslBuiltin {
    /// The builtin's callable name (e.g. `"stage"`, `"contract"`).
    pub name: String,
    /// Which builtin family the constructor belongs to.
    pub family: DslFamily,
    /// The first line of the builtin's Rust docstring, if any.
    pub summary: String,
    /// The remaining docstring body (dedented), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// The builtin's parameters, in signature order.
    pub params: Vec<DslParam>,
    /// The builtin's return type, as spelled by the Starlark type system.
    pub returns: String,
}

/// The builtin family a [`DslBuiltin`] belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DslFamily {
    /// Graph constructors: `stage` / `workflow` / `loop` / `branch` /
    /// `parallel` / topology / role / sandbox / memory / channel / bounds.
    Graph,
    /// Contract constructors: `contract` / `field` / `enum` / `list_of` /
    /// `variant` / `number` / `integer` / `string` / `json_skeleton`.
    Contract,
}

/// One parameter of a [`DslBuiltin`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DslParam {
    /// The parameter name (kwarg key). `*args` / `**kwargs` names carry no
    /// leading sigil; consult [`Self::kind`] to distinguish them.
    pub name: String,
    /// The parameter's declared type, as spelled by the Starlark type system.
    pub r#type: String,
    /// Whether the caller MUST supply this parameter.
    pub required: bool,
    /// The default value's Starlark `repr`, when the parameter is optional and
    /// carries a concrete default. Omitted for required params and for
    /// `Option`-typed params whose absence is simply "unset".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// The parameter's positional/named/variadic kind.
    pub kind: DslParamKind,
    /// The parameter's own docstring line, extracted from the builtin's
    /// docstring, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
}

/// The calling-convention kind of a [`DslParam`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DslParamKind {
    /// Positional-only (before a `/` marker).
    PositionalOnly,
    /// May be passed positionally or by name.
    PositionalOrNamed,
    /// The `*args` variadic.
    Args,
    /// Named-only (after a `*` marker).
    NamedOnly,
    /// The `**kwargs` variadic.
    Kwargs,
}

/// The contract grammar + decision-tag/verdict vocabulary the scalar builtin
/// signatures do not, on their own, spell out for an author.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DslGrammar {
    /// How `produces=` / `consumes=` contracts attach to a stage.
    pub contract: DslContractGrammar,
    /// The `loop(gate_verdict=..)` decision-tag vocabulary.
    pub verdict: DslVerdictGrammar,
}

/// The `produces=contract(..)` / `output_schema` grammar.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DslContractGrammar {
    /// The canonical `produces=` shape an author writes on a `stage`.
    pub produces_shape: String,
    /// The canonical `consumes=` shape (type-checked against upstream
    /// `produces=` at load time).
    pub consumes_shape: String,
    /// How a stage's checked `output_schema` is derived.
    pub output_schema: String,
    /// The constrained JSON-Schema subset that a lowered contract targets.
    pub schema_subset: Vec<String>,
}

/// The `loop(gate_verdict=..)` decision-tag vocabulary — how a review loop's
/// terminal tag is routed to approve / refine / block.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DslVerdictGrammar {
    /// The `gate_verdict={..}` dict shape.
    pub gate_verdict_shape: String,
    /// The role keys a `gate_verdict` dict declares.
    pub roles: Vec<DslVerdictRole>,
    /// The `field` key: the verdict field the terminal decision-tag is read
    /// from.
    pub field_key: String,
}

/// One decision-tag role in a `gate_verdict` dict.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DslVerdictRole {
    /// The role key (`"approve"` / `"refine"` / `"block"`).
    pub key: String,
    /// What matching this role's tag set does to the loop.
    pub meaning: String,
}

/// Build the machine-readable [`DslCatalog`] by reflecting the registered
/// builtin families.
///
/// The globals here carry ONLY kata's builtins (`GlobalsBuilder::new()`, not
/// `standard()`), so the catalog never leaks the Starlark stdlib surface — an
/// author sees exactly the kata DSL and nothing else.
pub fn dsl_catalog() -> DslCatalog {
    let mut builtins = Vec::new();
    collect_family(&mut builtins, DslFamily::Graph, kata_graph_globals);
    collect_family(&mut builtins, DslFamily::Contract, kata_contract_globals);
    // `documentation()` sorts within a family; a stable global sort keeps the
    // merged catalog deterministic regardless of family collection order.
    builtins.sort_by(|a, b| a.name.cmp(&b.name));

    DslCatalog {
        version: DSL_CATALOG_VERSION,
        builtins,
        grammar: grammar(),
        enum_domains: enum_domains(),
        limits: limits(),
    }
}

/// Reflect the closed enum domains from their typed authorities. Each domain's
/// `values` come from the authority the builtin parses through — a variant list
/// (derived where the type allows it) or the declared spelling table — so a new
/// variant appears here automatically. Sorted by domain name for a
/// deterministic catalog.
fn enum_domains() -> Vec<DslEnumDomain> {
    let mut domains = vec![
        DslEnumDomain {
            name: "cache_policy".to_owned(),
            values: CachePolicy::variants()
                .iter()
                .map(|v| v.as_tag().to_owned())
                .collect(),
        },
        DslEnumDomain {
            name: "progress_visibility".to_owned(),
            values: ProgressVisibility::variants()
                .iter()
                .map(|v| v.as_tag().to_owned())
                .collect(),
        },
        DslEnumDomain {
            name: "on_exhaustion".to_owned(),
            values: OnMaxAction::variants()
                .iter()
                .map(|v| v.as_tag().to_owned())
                .collect(),
        },
        DslEnumDomain {
            name: "exit_policy".to_owned(),
            values: ShellExitPolicy::variants()
                .iter()
                .map(|v| v.as_tag().to_owned())
                .collect(),
        },
        // The two closed sets `memory_snapshot(kind=.., status=..)`
        // accepts, listed from the same `all()` authorities the builtin
        // validates against so the published domain can never drift from the
        // parse set.
        DslEnumDomain {
            name: "memory_object_kind".to_owned(),
            values: kata_types::memory::MemoryObjectKind::all()
                .iter()
                .map(|k| k.label().to_owned())
                .collect(),
        },
        DslEnumDomain {
            name: "memory_object_status".to_owned(),
            values: kata_types::memory::MemoryObjectStatus::all()
                .iter()
                .map(|s| s.label().to_owned())
                .collect(),
        },
        // The closed sets the remaining string kwargs parse through, each read
        // off the authority the builtin consults.
        DslEnumDomain {
            name: "topology_mutation_policy".to_owned(),
            values: MutationPolicy::variants()
                .iter()
                .map(|p| p.label().to_owned())
                .collect(),
        },
        DslEnumDomain {
            name: "memory_writeback_scope".to_owned(),
            values: tags(kata_types::memory::MemoryScope::TIERS),
        },
        DslEnumDomain {
            name: "human_request_priority".to_owned(),
            values: HumanRequestPriority::variants()
                .iter()
                .map(|p| p.label().to_owned())
                .collect(),
        },
        DslEnumDomain {
            name: "cost_budget_mode".to_owned(),
            values: <kata_types::BudgetMode as strum::VariantArray>::VARIANTS
                .iter()
                .map(|mode| mode.label().to_owned())
                .collect(),
        },
        DslEnumDomain {
            name: "sandbox_profile_net".to_owned(),
            values: NetPolicy::SHIPPED
                .iter()
                .map(|n| n.label().to_owned())
                .collect(),
        },
        DslEnumDomain {
            name: "sandbox_profile_workspace".to_owned(),
            values: crate::parser::WORKSPACE_VIEWS
                .iter()
                .map(|(spelling, _)| (*spelling).to_owned())
                .collect(),
        },
        DslEnumDomain {
            name: "stage_op".to_owned(),
            values: WorkspaceEffectOp::variants()
                .iter()
                .map(|op| op.as_str().to_owned())
                .collect(),
        },
        // The string keys of `stage(execution_requirements={..})`: the
        // DECLARABLE sets, not each axis's `ALL` (a declaration may not name
        // `brokered_only`).
        DslEnumDomain {
            name: "execution_requirements_containment".to_owned(),
            values: tags(DECLARABLE_CONTAINMENT),
        },
        DslEnumDomain {
            name: "execution_requirements_network".to_owned(),
            values: tags(DECLARABLE_NETWORK),
        },
        DslEnumDomain {
            name: "execution_requirements_determinism".to_owned(),
            values: tags(DECLARABLE_DETERMINISM),
        },
        DslEnumDomain {
            name: "schedule_on_missed".to_owned(),
            values: MissedPolicy::variants()
                .iter()
                .map(|p| p.as_tag().to_owned())
                .collect(),
        },
    ];
    domains.sort_by(|a, b| a.name.cmp(&b.name));
    domains
}

fn tags(spellings: &[&str]) -> Vec<String> {
    spellings.iter().map(|s| (*s).to_owned()).collect()
}

/// Mirror the structured-output schema bounds from the single
/// `kata_types::agent_run` authority. A drift guard asserts each field equals
/// its source const so the published limit can never lie about the validator.
fn limits() -> DslLimits {
    DslLimits {
        max_schema_depth: agent_run::MAX_SCHEMA_DEPTH,
        max_schema_properties: agent_run::MAX_SCHEMA_PROPERTIES,
        max_schema_required: agent_run::MAX_SCHEMA_REQUIRED,
        max_array_items: agent_run::MAX_ARRAY_ITEMS,
        max_string_length: agent_run::MAX_STRING_LENGTH,
        max_enum_variants: agent_run::MAX_ENUM_VARIANTS,
        max_allowed_tools: agent_run::MAX_ALLOWED_TOOLS,
        max_tool_name_len: agent_run::MAX_TOOL_NAME_LEN,
    }
}

/// Reflect one builtin family into `out`.
fn collect_family(
    out: &mut Vec<DslBuiltin>,
    family: DslFamily,
    register: impl FnOnce(&mut GlobalsBuilder),
) {
    let globals = GlobalsBuilder::new().with(register).build();
    for (name, item) in globals.documentation().members {
        let DocItem::Member(DocMember::Function(func)) = item else {
            // The families register only functions; a non-function member would
            // be a new, unhandled builtin kind. Skip rather than mis-describe;
            // the coverage test catches any registered name that fails to
            // materialize as a catalog builtin.
            continue;
        };
        let (summary, details) = match &func.docs {
            Some(ds) => (ds.summary.clone(), ds.details.clone()),
            None => (String::new(), None),
        };
        out.push(DslBuiltin {
            name,
            family,
            summary,
            details,
            params: collect_params(&func.params),
            returns: func.ret.typ.to_string(),
        });
    }
}

/// Flatten a builtin's [`DocParams`] into ordered [`DslParam`]s.
fn collect_params(params: &DocParams) -> Vec<DslParam> {
    let mut out = Vec::new();
    for p in &params.pos_only {
        out.push(param(p, DslParamKind::PositionalOnly));
    }
    for p in &params.pos_or_named {
        out.push(param(p, DslParamKind::PositionalOrNamed));
    }
    if let Some(p) = &params.args {
        out.push(param(p, DslParamKind::Args));
    }
    for p in &params.named_only {
        out.push(param(p, DslParamKind::NamedOnly));
    }
    if let Some(p) = &params.kwargs {
        out.push(param(p, DslParamKind::Kwargs));
    }
    out
}

/// The Starlark sentinel `repr` for an `Option`-typed param whose absence means
/// "unset" (rendered by starlark as `...`). We drop it: such a param is optional
/// but carries no meaningful concrete default.
const OPTIONAL_SENTINEL: &str = "...";

fn param(p: &DocParam, kind: DslParamKind) -> DslParam {
    // `default_value.is_none()` ⇔ the param is `Required` (see starlark
    // `ParametersSpec::documentation_impl`). `*args` / `**kwargs` also report
    // `None` there but are never themselves required.
    let required =
        p.default_value.is_none() && !matches!(kind, DslParamKind::Args | DslParamKind::Kwargs);
    let default = match &p.default_value {
        Some(v) if v == OPTIONAL_SENTINEL => None,
        other => other.clone(),
    };
    DslParam {
        name: p.name.clone(),
        r#type: p.typ.to_string(),
        required,
        default,
        kind,
        doc: p.docs.as_ref().map(|ds| ds.summary.clone()),
    }
}

/// The static contract/verdict grammar. This spells out the multi-builtin
/// wiring (how `contract` attaches to a `stage`, and the `gate_verdict`
/// decision-tag vocabulary) that no single scalar signature captures.
fn grammar() -> DslGrammar {
    DslGrammar {
        contract: DslContractGrammar {
            produces_shape: "produces=contract(\"Name\", {\"field\": field(\"string\")})"
                .to_owned(),
            consumes_shape: "consumes=contract(\"Name\", {\"field\": field(\"string\")})"
                .to_owned(),
            output_schema:
                "A stage's `produces=` contract is lowered onto its checked `output_schema` \
                 (folding into the stage `contract_hash`). A `consumes=` contract is \
                 type-checked at load time against the `produces=` schema of a `depends_on` \
                 upstream."
                    .to_owned(),
            schema_subset: vec![
                "object: contract(name, {field: field(ty)})".to_owned(),
                "string / number / integer / bool / null primitives".to_owned(),
                "enum(a, b, ..) → {\"type\":\"string\",\"enum\":[..]}".to_owned(),
                format!(
                    "list_of(elem) → {{\"type\":\"array\",\"items\":<elem>,\"maxItems\":{DEFAULT_LIST_MAX_ITEMS}}}"
                ),
                "variant({tag: ty}) → {\"type\":\"variant\",\"variants\":{..}}".to_owned(),
                "number(min=,max=) / integer(min=,max=) inclusive range bounds".to_owned(),
                "string(pattern=,min_length=,max_length=) value constraints".to_owned(),
            ],
        },
        verdict: DslVerdictGrammar {
            gate_verdict_shape: "gate_verdict={\"field\": \"<verdict field>\", \"approve\": [..], \
                 \"refine\": [..], \"block\": [..]}"
                .to_owned(),
            field_key: "field".to_owned(),
            roles: vec![
                DslVerdictRole {
                    key: "approve".to_owned(),
                    meaning: "terminal tags that ACCEPT the loop result and exit successfully"
                        .to_owned(),
                },
                DslVerdictRole {
                    key: "refine".to_owned(),
                    meaning: "terminal tags that send the loop back for another refine iteration"
                        .to_owned(),
                },
                DslVerdictRole {
                    key: "block".to_owned(),
                    meaning: "terminal tags that REJECT the loop result (abort / escalate)"
                        .to_owned(),
                },
            ],
        },
    }
}

/// The set of registered builtin names, used by the coverage test to assert the
/// catalog omits nothing the evaluator wires in.
#[cfg(test)]
fn registered_builtin_names() -> Vec<String> {
    let mut names = Vec::new();
    for register in [
        kata_graph_globals as fn(&mut GlobalsBuilder),
        kata_contract_globals as fn(&mut GlobalsBuilder),
    ] {
        let globals = GlobalsBuilder::new().with(register).build();
        names.extend(globals.names().map(|n| n.as_str().to_owned()));
    }
    names.sort();
    names.dedup();
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Docstring phrasings that DENY a keyword. If one of these appears in a
    /// paragraph of a builtin's `details`, that paragraph is asserting the
    /// keyword it names is unavailable.
    const DENIAL_MARKERS: &[&str] = &[
        "NOT exposed",
        "not exposed",
        "does not accept",
        "does not take",
        "not accepted",
        "is not a kwarg",
    ];

    /// Word-boundary tokens of `text`, so a two-letter param name like `op`
    /// cannot match inside `topology` and `id` cannot match inside `identity`.
    fn word_tokens(text: &str) -> BTreeSet<&str> {
        text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|t| !t.is_empty())
            .collect()
    }

    /// DRIFT GUARD (`stage()`'s docstring said the opposite of its signature):
    /// no builtin's published prose may DENY a keyword that same builtin
    /// DECLARES.
    ///
    /// `stage()`'s details carried "The structured constructors (topology /
    /// sandbox / memory / validation / channels / human-requests) are
    /// deliberately NOT exposed here" while `topology=` and `sandbox=` sat on
    /// the signature immediately below it, both in `STAGE_KWARGS`, both fully
    /// lowered. Two readers of the SAME shipped surface diverged: the prose
    /// reader concluded `stage(sandbox=..)` was unavailable and reached for a
    /// workaround; the signature reader used it.
    ///
    /// Neither existing guard could see it. The full-catalog golden pins the
    /// bytes, so it only reports that prose CHANGED, never that it is false.
    /// The fail-closed drift check derives `params` from the same
    /// `Globals::documentation` reflection that emits the prose, so the two are
    /// never checked against each other. And this is not a comment-only defect:
    /// `details` is served live to agent authors over MCP
    /// (`dsl_catalog_resource_text`), which is the exact mechanism this module
    /// exists to provide.
    ///
    /// Derived, never hand-typed: both sides come from `dsl_catalog()`, so a
    /// newly-added kwarg is covered the moment it is declared.
    #[test]
    fn no_builtin_docstring_denies_a_keyword_it_declares() {
        let catalog = dsl_catalog();
        let mut offenders: Vec<String> = Vec::new();
        for builtin in &catalog.builtins {
            let Some(details) = builtin.details.as_deref() else {
                continue;
            };
            for paragraph in details.split("\n\n") {
                if !DENIAL_MARKERS.iter().any(|m| paragraph.contains(m)) {
                    continue;
                }
                let tokens = word_tokens(paragraph);
                for param in &builtin.params {
                    if tokens.contains(param.name.as_str()) {
                        offenders.push(format!(
                            "{}(): details deny {:?}, which the signature declares — {:?}",
                            builtin.name,
                            param.name,
                            paragraph.trim()
                        ));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "{} builtin docstring paragraph(s) deny a keyword the same builtin accepts. The \
             docstring is the contract an author reads (and the MCP `details` an agent author \
             targets), so it must not contradict the signature beside it:\n  {}",
            offenders.len(),
            offenders.join("\n  ")
        );
    }

    /// FAIL-CLOSED: the guard above actually detects. A denial sentence that
    /// names two kwargs `stage()` declares (`topology`, `sandbox`) is caught
    /// when replayed against `stage()`'s real parameter list, so a tokenizer or marker-list regression cannot leave
    /// the corpus assertion vacuously green.
    #[test]
    fn the_keyword_denial_guard_catches_the_sentence_that_shipped() {
        let catalog = dsl_catalog();
        let stage = catalog
            .builtins
            .iter()
            .find(|b| b.name == "stage")
            .expect("stage() is a registered builtin");
        let shipped = "The structured constructors (topology / sandbox / memory / validation / \
                       channels / human-requests) are deliberately NOT exposed here — they are \
                       declared elsewhere.";
        assert!(
            DENIAL_MARKERS.iter().any(|m| shipped.contains(m)),
            "the marker list must recognize the phrasing that shipped"
        );
        let tokens = word_tokens(shipped);
        let denied: Vec<&str> = stage
            .params
            .iter()
            .map(|p| p.name.as_str())
            .filter(|name| tokens.contains(name))
            .collect();
        assert_eq!(
            denied,
            vec!["topology", "sandbox"],
            "the guard must see exactly the two kwargs that sentence denied while the \
             signature declared them"
        );
    }

    /// FAIL-CLOSED coverage: every builtin the evaluator registers appears in
    /// the catalog. A new `#[starlark_module]` builtin without a catalog entry
    /// fails here rather than shipping an incomplete schema.
    #[test]
    fn catalog_covers_every_registered_builtin() {
        let catalog = dsl_catalog();
        let catalog_names: BTreeSet<&str> =
            catalog.builtins.iter().map(|b| b.name.as_str()).collect();
        let registered = registered_builtin_names();

        let missing: Vec<&String> = registered
            .iter()
            .filter(|n| !catalog_names.contains(n.as_str()))
            .collect();
        assert!(
            missing.is_empty(),
            "catalog is missing registered builtin(s): {missing:?}; \
             every registered DSL builtin must materialize a catalog entry"
        );
        assert_eq!(
            catalog.builtins.len(),
            registered.len(),
            "catalog builtin count ({}) must equal registered builtin count ({})",
            catalog.builtins.len(),
            registered.len()
        );
    }

    /// The catalog names the load-bearing constructors from BOTH families, so a
    /// regression that drops a family (or a whole builtin) is caught by name.
    #[test]
    fn catalog_names_the_core_constructors() {
        let catalog = dsl_catalog();
        let by_name: std::collections::HashMap<&str, &DslBuiltin> = catalog
            .builtins
            .iter()
            .map(|b| (b.name.as_str(), b))
            .collect();

        for graph in ["stage", "workflow", "loop", "branch", "parallel"] {
            let b = by_name
                .get(graph)
                .unwrap_or_else(|| panic!("catalog must contain graph builtin {graph:?}"));
            assert_eq!(b.family, DslFamily::Graph, "{graph} is a graph builtin");
        }
        for contract in [
            "contract", "field", "enum", "list_of", "variant", "number", "integer", "string",
        ] {
            let b = by_name
                .get(contract)
                .unwrap_or_else(|| panic!("catalog must contain contract builtin {contract:?}"));
            assert_eq!(
                b.family,
                DslFamily::Contract,
                "{contract} is a contract builtin"
            );
        }
    }

    /// The typed signatures round-trip: `contract(name, fields)` is the two
    /// positional-only params the Rust builtin declares, and `field(ty, ...)`
    /// carries its `required` default. This ties the catalog to the actual
    /// `#[starlark_module]` param shape, not a hand-copy.
    #[test]
    fn catalog_round_trips_typed_signatures() {
        let catalog = dsl_catalog();
        let by_name: std::collections::HashMap<&str, &DslBuiltin> = catalog
            .builtins
            .iter()
            .map(|b| (b.name.as_str(), b))
            .collect();

        let contract = by_name["contract"];
        assert_eq!(contract.params.len(), 2, "contract(name, fields)");
        assert_eq!(contract.params[0].name, "name");
        assert!(contract.params[0].required, "contract name is required");
        assert_eq!(contract.params[0].kind, DslParamKind::PositionalOnly);
        assert_eq!(contract.params[1].name, "fields");
        assert_eq!(contract.params[1].kind, DslParamKind::PositionalOnly);

        let field = by_name["field"];
        let required_param = field
            .params
            .iter()
            .find(|p| p.name == "required")
            .expect("field() declares a `required` kwarg");
        assert!(
            !required_param.required,
            "field(required=..) is itself optional"
        );
        // `Option<bool>`, so the catalog carries no CONCRETE default even though
        // the documented behaviour of an unspelled `required=` is `True`. The
        // `Option` is load-bearing rather than stylistic: `field()` rejects
        // `default=` beside an EXPLICIT `required=True` and `secret=True` beside
        // an EXPLICIT `required=False`, and a plain `bool` makes both
        // indistinguishable from the ordinary unspelled form — which is exactly
        // how those rejections came to be documented but unwritable.
        assert_eq!(
            required_param.default, None,
            "field(required=..) is an Option kwarg: no concrete default in the catalog"
        );
        assert_eq!(required_param.kind, DslParamKind::NamedOnly);

        // `number(min, max)` are Option kwargs → optional, no concrete default.
        let number = by_name["number"];
        let min = number
            .params
            .iter()
            .find(|p| p.name == "min")
            .expect("number(min=..)");
        assert!(!min.required, "number min is optional");
        assert_eq!(
            min.default, None,
            "Option kwarg carries no concrete default"
        );
    }

    /// Deterministic: two builds render byte-identical JSON, and builtins are
    /// name-sorted.
    #[test]
    fn catalog_is_deterministic_and_sorted() {
        let a = serde_json::to_string(&dsl_catalog()).unwrap();
        let b = serde_json::to_string(&dsl_catalog()).unwrap();
        assert_eq!(a, b, "catalog JSON must be deterministic across builds");

        let catalog = dsl_catalog();
        let mut sorted = catalog.builtins.clone();
        sorted.sort_by(|x, y| x.name.cmp(&y.name));
        assert_eq!(
            catalog.builtins, sorted,
            "catalog builtins must be emitted in name order"
        );
        assert_eq!(catalog.version, DSL_CATALOG_VERSION);
    }

    /// The grammar section carries the contract wiring and the full
    /// decision-tag/verdict vocabulary (`field` + approve/refine/block).
    #[test]
    fn catalog_grammar_declares_verdict_vocabulary() {
        let catalog = dsl_catalog();
        let roles: BTreeSet<&str> = catalog
            .grammar
            .verdict
            .roles
            .iter()
            .map(|r| r.key.as_str())
            .collect();
        assert_eq!(
            roles,
            BTreeSet::from(["approve", "refine", "block"]),
            "verdict vocabulary must cover approve/refine/block"
        );
        assert_eq!(catalog.grammar.verdict.field_key, "field");
        assert!(!catalog.grammar.contract.produces_shape.is_empty());
        assert!(!catalog.grammar.contract.schema_subset.is_empty());
    }

    /// The catalog serializes to a JSON object with the stable top-level keys,
    /// INCLUDING the additive `enum_domains` + `limits` sections (schema version
    /// stays 1 — these are additive).
    #[test]
    fn catalog_serializes_to_stable_shape() {
        let value = serde_json::to_value(dsl_catalog()).unwrap();
        assert_eq!(value["version"], DSL_CATALOG_VERSION);
        assert!(value.get("builtins").and_then(|b| b.as_array()).is_some());
        assert!(value.get("grammar").is_some());
        assert!(
            value
                .get("enum_domains")
                .and_then(|d| d.as_array())
                .is_some(),
            "catalog publishes the enum domains"
        );
        assert!(
            value.get("limits").and_then(|l| l.as_object()).is_some(),
            "catalog publishes the schema-limits block"
        );
        let first = &value["builtins"][0];
        for key in ["name", "family", "summary", "params", "returns"] {
            assert!(first.get(key).is_some(), "builtin must carry {key:?}");
        }
    }

    /// Each closed string kwarg's published domain is what its builtin accepts,
    /// read through the evaluator rather than through the authority: every
    /// published value evaluates, and each of a fixed set of near misses is
    /// refused naming the kwarg — the upper-case, leading-space and
    /// trailing-space form of every published value, every OTHER domain's
    /// values, and one arbitrary non-member. `cost_budget`'s mode is judged
    /// twice, by its builtin and by the lowering a `cost_budget={..}` dict
    /// reaches. Where the spelling is a serde tag, the domain also equals the
    /// serializer's tags, an oracle that shares no code with the labels.
    ///
    /// **Would red if:** a published value were refused; a parser folded case
    /// or trimmed whitespace, or admitted another domain's spelling; or an
    /// authority's labels drifted from serde. An arbitrary extra spelling
    /// outside that probe set (a parser admitting `"fire_always"`, say) stays
    /// green: the guard against it is structural — each builtin parses through
    /// the one authority this catalog publishes.
    #[test]
    fn every_closed_string_kwarg_domain_is_its_builtins_parse_set() {
        let domains = enum_domains();
        let domain = |name: &str| -> Vec<String> {
            domains
                .iter()
                .find(|d| d.name == name)
                .unwrap_or_else(|| panic!("domain {name} is published"))
                .values
                .clone()
        };
        // A fresh stage id per probe: the stage builder refuses a repeat.
        static PROBE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        // A builtin call alone, evaluated against the graph globals: the
        // kwarg's spelling is judged by the builtin, with no graph-level check
        // (a `promote`'s criterion, say) standing between.
        let call = |expr: String| -> Result<(), String> {
            let ast = starlark::syntax::AstModule::parse(
                "probe.star",
                format!("probe = {expr}\n"),
                &starlark::syntax::Dialect::Standard,
            )
            .map_err(|e| e.to_string())?;
            let globals = GlobalsBuilder::standard().with(kata_graph_globals).build();
            let module = starlark::environment::Module::new();
            let mut eval = starlark::eval::Evaluator::new(&module);
            eval.eval_module(ast, &globals)
                .map(|_| ())
                .map_err(|e| e.to_string())
        };
        // A whole workflow, for the kwargs judged where a profile lowers.
        let lowered = |profile: String| -> Result<(), String> {
            crate::starlark_eval::evaluate_starlark_checked(
                &format!(
                    "only = stage(id = \"only\", agent = \"shell\", run = \"true\", \
                     sandbox = sandbox_profile({profile}))\n\
                     workflow(\"probe\", root = [only])\n"
                ),
                "probe.star",
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
        };
        // A whole workflow, for a workflow-level kwarg its lowering judges.
        let lowered_workflow = |kwarg: String| -> Result<(), String> {
            crate::starlark_eval::evaluate_starlark_checked(
                &format!(
                    "only = stage(id = \"only\", agent = \"shell\", run = \"true\")\n\
                     workflow(\"probe\", root = [only], {kwarg})\n"
                ),
                "probe.star",
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
        };
        // A stage declaring one `execution_requirements` key.
        let requirement = |key: &str, v: &str| -> Result<(), String> {
            let id = PROBE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            call(format!(
                "stage(id = \"er{id}\", agent = \"shell\", run = \"true\", \
                 execution_requirements = {{\"{key}\": \"{v}\"}})"
            ))
        };
        type Probe<'a> = Box<dyn Fn(&str) -> Result<(), String> + 'a>;
        // (domain, kwarg its refusal names, probe for one spelling)
        let cases: Vec<(&str, &str, Probe)> = vec![
            (
                "topology_mutation_policy",
                "mutation_policy",
                Box::new(|v| call(format!("topology(\"k\", mutation_policy = \"{v}\")"))),
            ),
            (
                "memory_writeback_scope",
                "scope",
                Box::new(|v| call(format!("memory_writeback(\"m\", scope = \"{v}\")"))),
            ),
            (
                "human_request_priority",
                "priority",
                Box::new(|v| {
                    call(format!(
                        "human_request(\"h\", question = \"q\", \
                         default_assumption = \"d\", priority = \"{v}\")"
                    ))
                }),
            ),
            (
                "cost_budget_mode",
                "mode",
                Box::new(|v| call(format!("cost_budget(\"{v}\", limit_usd = 1.0)"))),
            ),
            (
                "schedule_on_missed",
                "on_missed",
                Box::new(|v| {
                    call(format!(
                        "schedule(id = \"s\", submit = \"t\", every_ms = 1000, \
                         on_missed = \"{v}\")"
                    ))
                }),
            ),
            (
                "stage_op",
                "op",
                Box::new(|v| {
                    let id = PROBE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    call(format!(
                        "stage(id = \"fx{id}\", agent = \"workspace_effect\", op = \"{v}\")"
                    ))
                }),
            ),
            (
                "sandbox_profile_net",
                "net",
                Box::new(|v| lowered(format!("net = \"{v}\""))),
            ),
            (
                "sandbox_profile_workspace",
                "workspace",
                Box::new(|v| lowered(format!("workspace = \"{v}\""))),
            ),
            (
                "cost_budget_mode",
                "cost_budget.mode",
                Box::new(|v| {
                    lowered_workflow(format!(
                        "cost_budget = {{\"mode\": \"{v}\", \"limit_usd\": 1.0}}"
                    ))
                }),
            ),
            (
                "execution_requirements_containment",
                "containment",
                Box::new(|v| requirement("containment", v)),
            ),
            (
                "execution_requirements_network",
                "network",
                Box::new(|v| requirement("network", v)),
            ),
            (
                "execution_requirements_determinism",
                "determinism",
                Box::new(|v| requirement("determinism", v)),
            ),
        ];
        for (name, kwarg, probe) in &cases {
            let values = domain(name);
            assert!(!values.is_empty(), "{name} publishes values");
            for value in &values {
                if let Err(error) = probe(value) {
                    panic!("{name} ({kwarg}): the published {value:?} is refused: {error}");
                }
            }
            let mut near_misses = BTreeSet::from(["not_a_spelling".to_owned()]);
            for value in &values {
                near_misses.insert(value.to_uppercase());
                near_misses.insert(format!(" {value}"));
                near_misses.insert(format!("{value} "));
            }
            for other in domains.iter().flat_map(|d| &d.values) {
                if !values.contains(other) {
                    near_misses.insert(other.clone());
                }
            }
            for spelling in &near_misses {
                let Err(error) = probe(spelling) else {
                    panic!("{name} ({kwarg}): the unpublished {spelling:?} is admitted");
                };
                // The traceback echoes the source line; judge the message itself.
                let message = error
                    .lines()
                    .find(|line| line.trim_start().starts_with("error:"))
                    .unwrap_or(&error);
                assert!(
                    message.contains(kwarg),
                    "{name}: the refusal of {spelling:?} names {kwarg}: {error}"
                );
            }
        }

        let serde_tags = |values: Vec<serde_json::Value>| -> Vec<String> {
            values
                .into_iter()
                .map(|v| v.as_str().expect("a string tag").to_owned())
                .collect()
        };
        assert_eq!(
            domain("topology_mutation_policy"),
            serde_tags(
                MutationPolicy::variants()
                    .iter()
                    .map(|p| serde_json::to_value(p).unwrap())
                    .collect()
            )
        );
        assert_eq!(
            domain("human_request_priority"),
            serde_tags(
                HumanRequestPriority::variants()
                    .iter()
                    .map(|p| serde_json::to_value(p).unwrap())
                    .collect()
            )
        );
        assert_eq!(
            domain("schedule_on_missed"),
            serde_tags(
                MissedPolicy::variants()
                    .iter()
                    .map(|p| serde_json::to_value(p).unwrap())
                    .collect()
            )
        );
        assert_eq!(
            domain("stage_op"),
            serde_tags(
                WorkspaceEffectOp::variants()
                    .iter()
                    .map(|op| serde_json::to_value(op).unwrap())
                    .collect()
            )
        );
        assert_eq!(
            domain("sandbox_profile_net"),
            NetPolicy::SHIPPED
                .iter()
                .map(|n| serde_json::to_value(n).unwrap()["kind"]
                    .as_str()
                    .unwrap()
                    .to_owned())
                .collect::<Vec<_>>()
        );
    }

    /// DRIFT GUARD (enum-domain): the catalog's published enum domains are
    /// EXACTLY the typed authorities' `variants().as_tag()` — a new enum variant
    /// (or a spelling change) that skips the authority accessor fails here rather
    /// than shipping a catalog that lies about the accepted spellings.
    #[test]
    fn catalog_enum_domains_reflect_authorities() {
        let domains = enum_domains();
        let by_name: std::collections::HashMap<&str, &Vec<String>> = domains
            .iter()
            .map(|d| (d.name.as_str(), &d.values))
            .collect();

        let cache: Vec<&str> = CachePolicy::variants()
            .iter()
            .map(CachePolicy::as_tag)
            .collect();
        let progress: Vec<&str> = ProgressVisibility::variants()
            .iter()
            .map(ProgressVisibility::as_tag)
            .collect();
        let on_exhaustion: Vec<&str> = OnMaxAction::variants()
            .iter()
            .map(OnMaxAction::as_tag)
            .collect();
        let exit_policy: Vec<&str> = ShellExitPolicy::variants()
            .iter()
            .map(ShellExitPolicy::as_tag)
            .collect();

        assert_eq!(
            by_name["cache_policy"]
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            cache,
            "cache_policy domain must reflect CachePolicy::variants()"
        );
        assert_eq!(
            by_name["exit_policy"]
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            exit_policy,
            "exit_policy domain must reflect ShellExitPolicy::variants()"
        );
        assert_eq!(
            by_name["progress_visibility"]
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            progress,
            "progress_visibility domain must reflect ProgressVisibility::variants()"
        );
        assert_eq!(
            by_name["on_exhaustion"]
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            on_exhaustion,
            "on_exhaustion domain must reflect OnMaxAction::variants()"
        );
        // Domains are name-sorted (deterministic catalog).
        let mut sorted = domains.clone();
        sorted.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(domains, sorted, "enum domains must be emitted name-sorted");
    }

    /// DRIFT GUARD (decode-roundtrip): every published enum spelling round-trips
    /// through the SAME typed decoder the load-time DSL uses — so a spelling the
    /// catalog advertises is one the evaluator actually accepts, and vice versa.
    #[test]
    fn catalog_enum_spellings_round_trip_through_decoders() {
        for policy in CachePolicy::variants() {
            let tag = policy.as_tag();
            // serde tag == as_tag(), and the tag decodes back to the variant.
            assert_eq!(
                serde_json::to_value(policy).unwrap(),
                serde_json::json!(tag)
            );
            let decoded: CachePolicy =
                serde_json::from_value(serde_json::json!(tag)).expect("tag decodes");
            assert_eq!(decoded, *policy, "cache_policy {tag:?} must round-trip");
        }
        for vis in ProgressVisibility::variants() {
            let tag = vis.as_tag();
            assert_eq!(serde_json::to_value(vis).unwrap(), serde_json::json!(tag));
            let decoded: ProgressVisibility =
                serde_json::from_value(serde_json::json!(tag)).expect("tag decodes");
            assert_eq!(decoded, *vis, "progress_visibility {tag:?} must round-trip");
        }
        for action in OnMaxAction::variants() {
            let tag = action.as_tag();
            // on_exhaustion is authored as a bare spelling via parse_on_max, and
            // serde-serializes to the same snake_case tag.
            assert_eq!(
                serde_json::to_value(action).unwrap(),
                serde_json::json!(tag)
            );
            assert_eq!(
                kata_types::review_loop::ReviewLoop::parse_on_max(tag),
                Some(*action),
                "on_exhaustion {tag:?} must parse back to its variant"
            );
        }
        for policy in ShellExitPolicy::variants() {
            let tag = policy.as_tag();
            assert_eq!(
                serde_json::to_value(policy).unwrap(),
                serde_json::json!(tag)
            );
            let decoded: ShellExitPolicy =
                serde_json::from_value(serde_json::json!(tag)).expect("tag decodes");
            assert_eq!(decoded, *policy, "exit_policy {tag:?} must round-trip");
        }
    }

    /// DRIFT GUARD (bounds-single-source): the `list_of` max-items bound has ONE
    /// authority. The DSL codegen default, the agent-run validator ceiling, and
    /// the catalog's published limit are the SAME number — a re-hardcode of any
    /// of the three that diverges fails here.
    #[test]
    fn list_max_items_is_single_sourced() {
        assert_eq!(
            DEFAULT_LIST_MAX_ITEMS,
            agent_run::MAX_ARRAY_ITEMS,
            "the DSL list_of default must equal the agent-run validator ceiling"
        );
        assert_eq!(
            limits().max_array_items,
            agent_run::MAX_ARRAY_ITEMS,
            "the catalog's published max_array_items must equal the authority"
        );
        // The grammar's human-readable list_of subset line renders the same bound.
        let catalog = dsl_catalog();
        assert!(
            catalog
                .grammar
                .contract
                .schema_subset
                .iter()
                .any(|line| line.contains(&format!("maxItems\":{DEFAULT_LIST_MAX_ITEMS}"))),
            "the list_of schema-subset line must render the single-sourced bound"
        );
    }

    /// DRIFT GUARD (limits authority): every published limit mirrors its
    /// `kata_types::agent_run` source const exactly.
    #[test]
    fn catalog_limits_mirror_agent_run_authority() {
        let limits = limits();
        assert_eq!(limits.max_schema_depth, agent_run::MAX_SCHEMA_DEPTH);
        assert_eq!(
            limits.max_schema_properties,
            agent_run::MAX_SCHEMA_PROPERTIES
        );
        assert_eq!(limits.max_schema_required, agent_run::MAX_SCHEMA_REQUIRED);
        assert_eq!(limits.max_array_items, agent_run::MAX_ARRAY_ITEMS);
        assert_eq!(limits.max_string_length, agent_run::MAX_STRING_LENGTH);
        assert_eq!(limits.max_enum_variants, agent_run::MAX_ENUM_VARIANTS);
        assert_eq!(limits.max_allowed_tools, agent_run::MAX_ALLOWED_TOOLS);
        assert_eq!(limits.max_tool_name_len, agent_run::MAX_TOOL_NAME_LEN);
    }

    /// FULL-CATALOG GOLDEN: the entire machine-readable catalog is pinned to a
    /// checked-in JSON golden, so ANY change to a builtin signature, docstring,
    /// enum domain, or limit is a visible, reviewed diff rather than a silent
    /// drift. Regenerate intentionally with
    /// `UPDATE_DSL_CATALOG_GOLDEN=1 just test-one-crate kata-program catalog`
    /// — HYPHENATED. `kata_program` is not a package name and `cargo` exits 101
    /// on it, which reads as a broken test rather than a mistyped recipe.
    #[test]
    fn full_catalog_matches_golden() {
        let golden_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/goldens/dsl_catalog.json"
        );
        let mut actual = serde_json::to_string_pretty(&dsl_catalog())
            .expect("catalog serializes to pretty JSON");
        actual.push('\n');
        if std::env::var_os("UPDATE_DSL_CATALOG_GOLDEN").is_some() {
            std::fs::write(golden_path, &actual).expect("write DSL catalog golden");
        }
        let expected = std::fs::read_to_string(golden_path).unwrap_or_default();
        assert_eq!(
            actual, expected,
            "DSL catalog drifted from its golden ({golden_path}); if intended, \
             regenerate with UPDATE_DSL_CATALOG_GOLDEN=1"
        );
    }
}
