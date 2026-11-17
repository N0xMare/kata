//! Typed workflow **invocation params** — declaration, resolution, and
//! the durable invocation row.
//!
//! A workflow declares a set of named, typed parameters via
//! `workflow(params={name: field(..)})`. At submit time EVERY face (CLI / MCP /
//! REST / client / schedule / child / resume) funnels the caller-supplied values
//! through the ONE resolver here ([`resolve_and_validate_params`]), which does
//! strict unknown-key + type checking against the declared schema, fills
//! defaults, and produces the canonical, sorted [`InvocationParam`] rows that
//! ride inside the immutable `ExecutionInvocation` — so the durable input digest
//! (the admission hash) binds the resolved inputs automatically and identically
//! across every face.
//!
//! # What lives here vs. elsewhere
//!
//! - The param TYPE vocabulary reuses the constrained `output_schema` subset the
//!   agent-run validator already owns
//!   ([`crate::agent_run::validate_param_value_against_schema`], the non-object
//!   node variant), so a param's declared type is exactly the JSON-Schema node
//!   `field(..)` / `string(..)` / `integer(..)` / `enum(..)` lower to. There is
//!   no second type language.
//! - The declared spec ([`WorkflowParamSpec`]) is authored in the pack and rides
//!   the checked `ExecutionProgram` (folded into its hash), so the resolver can
//!   re-validate against it at the executor boundary and on recovery.
//! - The resolved rows ([`InvocationParam`]) carry ONLY `name` + `value`: those
//!   are the input identity. Provenance (which face supplied the value) is
//!   recorded BESIDE the digest in admission evidence, never hashed, so two faces
//!   supplying identical values converge to one digest. The secret marker is a
//!   pure function of the program spec and is looked up there by its readers;
//!   it is deliberately not duplicated onto the durable row.

use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

use crate::agent_run::validate_param_value_against_schema;

/// Maximum number of declared params a workflow may accept, and the maximum
/// number of supplied values one invocation may carry. Bounded independently of
/// any face's request limits so a forged caller cannot turn the resolver into an
/// unbounded allocation.
pub const MAX_INVOCATION_PARAMS: usize = 64;

/// Maximum canonical-JSON byte length of a single resolved param value.
pub const MAX_PARAM_VALUE_BYTES: usize = 64 * 1024;

/// The face an invocation param value entered through.
///
/// Recorded BESIDE the admission digest (in admission evidence / operator
/// projections), never folded into it: identical values from two faces must
/// produce one digest. The seven faces mirror the params conformance matrix.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamProvenance {
    /// `POST /api/v1/executions` request body.
    Rest,
    /// Typed `KataClient` SDK submit.
    Client,
    /// `kata run --param ..` operator CLI.
    Cli,
    /// MCP `tools/call name=run` (op-contract `RunRequest`).
    Mcp,
    /// A durable `schedule(..)` fire, re-validated at fire time.
    ///
    /// Precisely: the params were resolved ONCE, at install, into the invocation the durable
    /// schedule row PINS; the fire decodes those pinned bytes and re-runs the admission chokepoint
    /// over THEM — never against a recompile of the target pack. Over a fixed input the
    /// re-validation is a fixed point, so it can only confirm or refuse, and a schedule's admission
    /// digest is identical across every fire and every restart.
    Schedule,
    /// A `subworkflow(params={..})` child spawn (authored constants).
    Child,
    /// Recovery republish of a durably-admitted invocation.
    Resume,
}

impl ParamProvenance {
    /// Stable snake_case label matching the serde representation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rest => "rest",
            Self::Client => "client",
            Self::Cli => "cli",
            Self::Mcp => "mcp",
            Self::Schedule => "schedule",
            Self::Child => "child",
            Self::Resume => "resume",
        }
    }
}

impl std::fmt::Display for ParamProvenance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One declared workflow parameter: a name, its constrained JSON-Schema type
/// node, and required/default/secret metadata.
///
/// The `schema` is exactly the `output_schema`-subset node the DSL `field(..)` /
/// `string(..)` / `integer(..)` / `enum(..)` builtins lower to, so the resolver
/// validates supplied values with
/// [`crate::agent_run::validate_param_value_against_schema`], over the same
/// constrained subset the structured-output membrane uses. Authored in the pack and carried on the
/// checked `ExecutionProgram` (folded into its hash).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowParamSpec {
    /// Parameter name (the invocation key). Unique within a workflow.
    pub name: SmolStr,
    /// The constrained `output_schema`-subset type node.
    pub schema: serde_json::Value,
    /// `true` when the param must be supplied (unless a `default` fills it).
    pub required: bool,
    /// The author-declared default value, already schema-valid. Present iff the
    /// param is optional-with-a-default. A secret param never carries a default
    /// (a plaintext secret must not live in pack source).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,
    /// `true` when the value is a secret: a refusal never echoes it, and the
    /// authoritative invocation blob keeps the real value. A secret param must
    /// be supplied at every invocation.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub secret: bool,
    /// The `field(doc=..)` docstring, surfaced to operators. Never a value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
}

/// One resolved invocation param row: the DURABLE, digest-bound input identity.
///
/// Carries ONLY `name` + `value` — those are what the admission digest binds.
/// Rows are stored in canonical (name-sorted) order inside `ExecutionInvocation`
/// so the same resolved set always canonicalizes to the same bytes regardless of
/// the order the face supplied them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationParam {
    /// Parameter name (matches a declared [`WorkflowParamSpec::name`]).
    pub name: SmolStr,
    /// The resolved value: the supplied value, or the declared default.
    pub value: serde_json::Value,
}

/// A typed param-resolution refusal. Every variant maps to a STABLE `param.*`
/// code ([`Self::code`]) every face reports identically, so a bad invocation is
/// rejected with the same machine-readable reason on CLI, MCP, REST, client,
/// schedule, and child faces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParamError {
    /// A supplied key names no declared param.
    UnknownKey { name: String },
    /// A required param (no default) was not supplied.
    MissingRequired { name: String },
    /// A supplied value does not satisfy the param's declared schema.
    TypeMismatch { name: String, detail: String },
    /// A declared param schema is itself outside the supported subset.
    SchemaInvalid { name: String, detail: String },
    /// More params were supplied (or declared) than the bound allows.
    TooMany { count: usize, max: usize },
    /// A supplied value's canonical encoding exceeds the per-value byte bound.
    ValueTooLarge {
        name: String,
        bytes: usize,
        max: usize,
    },
    /// A secret param was not supplied (secrets are never defaulted).
    SecretRequired { name: String },
}

impl ParamError {
    /// The STABLE machine-readable refusal code, identical across every face.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnknownKey { .. } => "param.unknown_key",
            Self::MissingRequired { .. } => "param.missing_required",
            Self::TypeMismatch { .. } => "param.type_mismatch",
            Self::SchemaInvalid { .. } => "param.schema_invalid",
            Self::TooMany { .. } => "param.too_many",
            Self::ValueTooLarge { .. } => "param.value_too_large",
            Self::SecretRequired { .. } => "param.secret_required",
        }
    }
}

impl std::fmt::Display for ParamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = self.code();
        match self {
            Self::UnknownKey { name } => {
                write!(f, "{code}: unknown workflow param {name:?}")
            }
            Self::MissingRequired { name } => {
                write!(f, "{code}: missing required workflow param {name:?}")
            }
            Self::TypeMismatch { name, detail } => {
                write!(f, "{code}: workflow param {name:?} type mismatch: {detail}")
            }
            Self::SchemaInvalid { name, detail } => {
                write!(
                    f,
                    "{code}: workflow param {name:?} declares an invalid schema: {detail}"
                )
            }
            Self::TooMany { count, max } => {
                write!(
                    f,
                    "{code}: {count} workflow params supplied; maximum is {max}"
                )
            }
            Self::ValueTooLarge { name, bytes, max } => {
                write!(
                    f,
                    "{code}: workflow param {name:?} value is {bytes} bytes; maximum is {max}"
                )
            }
            Self::SecretRequired { name } => {
                write!(f, "{code}: secret workflow param {name:?} must be supplied")
            }
        }
    }
}

impl std::error::Error for ParamError {}

/// Resolve + strictly validate caller-supplied param values against a workflow's
/// declared param specs, filling defaults, and produce the canonical, sorted
/// durable [`InvocationParam`] rows.
///
/// This is the ONE resolver every face funnels through, so the resolved map, the
/// refusal codes, and therefore the admission digest are identical no matter
/// which face supplied the values. Rules, in order:
///
/// 1. Bound the count of both supplied and declared params ([`ParamError::TooMany`]).
/// 2. Every declared schema must be valid ([`ParamError::SchemaInvalid`]).
/// 3. Every supplied key must name a declared param ([`ParamError::UnknownKey`]).
/// 4. For each declared param, in name order:
///    - supplied → validate the value against the declared schema
///      ([`ParamError::TypeMismatch`]) and bound its size
///      ([`ParamError::ValueTooLarge`]);
///    - not supplied + secret → [`ParamError::SecretRequired`];
///    - not supplied + has a default → use the default;
///    - not supplied + required → [`ParamError::MissingRequired`];
///    - not supplied + optional-no-default → omit the row.
///
/// The returned rows are sorted by name (canonical order); the same resolved set
/// always yields the same rows regardless of supplied order.
///
/// # Errors
///
/// Returns the first [`ParamError`] encountered; the resolution is deterministic
/// so the first refusal is stable across faces.
pub fn resolve_and_validate_params(
    specs: &[WorkflowParamSpec],
    supplied: &serde_json::Map<String, serde_json::Value>,
) -> Result<Vec<InvocationParam>, ParamError> {
    if specs.len() > MAX_INVOCATION_PARAMS {
        return Err(ParamError::TooMany {
            count: specs.len(),
            max: MAX_INVOCATION_PARAMS,
        });
    }
    if supplied.len() > MAX_INVOCATION_PARAMS {
        return Err(ParamError::TooMany {
            count: supplied.len(),
            max: MAX_INVOCATION_PARAMS,
        });
    }

    // Unknown-key check first: a caller that supplies a key naming no declared
    // param is refused before any value is used, on every face.
    for key in supplied.keys() {
        if !specs.iter().any(|spec| spec.name.as_str() == key) {
            return Err(ParamError::UnknownKey { name: key.clone() });
        }
    }

    // Resolve declared params in NAME order so the rows are canonical regardless
    // of declaration or supply order.
    let mut ordered: Vec<&WorkflowParamSpec> = specs.iter().collect();
    ordered.sort_by(|a, b| a.name.cmp(&b.name));

    let mut rows = Vec::with_capacity(ordered.len());
    for spec in ordered {
        let name = spec.name.as_str();
        match supplied.get(name) {
            Some(value) => {
                validate_param_value_against_schema(value, &spec.schema).map_err(|detail| {
                    // A schema the resolver cannot even parse surfaces as
                    // schema_invalid; a value that fails an otherwise-valid
                    // schema surfaces as a type mismatch.
                    if is_schema_invalid_detail(&detail) {
                        ParamError::SchemaInvalid {
                            name: name.to_owned(),
                            detail: detail.clone(),
                        }
                    } else if spec.secret {
                        // SECRET-SAFE REFUSAL: the shared validator's value
                        // messages echo the offending value (enum membership,
                        // pattern, min/max bounds, variant tags). A mistyped
                        // SECRET must never land its value in a REST 400 body /
                        // MCP usage error / CLI stderr / schedule-fire log, so
                        // the detail is withheld for a secret param — the stable
                        // code and the field NAME are all a caller gets.
                        ParamError::TypeMismatch {
                            name: name.to_owned(),
                            detail: format!(
                                "secret param {name:?} does not satisfy its declared schema; \
                                 detail withheld"
                            ),
                        }
                    } else {
                        ParamError::TypeMismatch {
                            name: name.to_owned(),
                            detail,
                        }
                    }
                })?;
                let bytes = serde_json::to_vec(value).map_or(usize::MAX, |b| b.len());
                if bytes > MAX_PARAM_VALUE_BYTES {
                    return Err(ParamError::ValueTooLarge {
                        name: name.to_owned(),
                        bytes,
                        max: MAX_PARAM_VALUE_BYTES,
                    });
                }
                rows.push(InvocationParam {
                    name: spec.name.clone(),
                    value: value.clone(),
                });
            }
            None if spec.secret => {
                return Err(ParamError::SecretRequired {
                    name: name.to_owned(),
                });
            }
            None => {
                if let Some(default) = &spec.default {
                    rows.push(InvocationParam {
                        name: spec.name.clone(),
                        value: default.clone(),
                    });
                } else if spec.required {
                    return Err(ParamError::MissingRequired {
                        name: name.to_owned(),
                    });
                }
                // optional, no default, not supplied → omit the row.
            }
        }
    }

    Ok(rows)
}

/// Build the per-param PROVENANCE evidence rows recorded beside the
/// admission digest — `{name, source_face, secret}` for each RESOLVED param,
/// never the value.
///
/// The secret marker is looked up in the program's declared specs; `source_face`
/// is the face the values entered through at THIS admission (a recovery
/// republish records [`ParamProvenance::Resume`]). Deliberately NOT part of the
/// invocation bytes, so provenance never rotates the admission digest.
#[must_use]
pub fn param_provenance_evidence(
    params: &[InvocationParam],
    specs: &[WorkflowParamSpec],
    source_face: ParamProvenance,
) -> Vec<crate::execution::ExecutionParamProvenanceEvidence> {
    params
        .iter()
        .map(|param| crate::execution::ExecutionParamProvenanceEvidence {
            name: param.name.clone(),
            source_face,
            secret: specs
                .iter()
                .any(|spec| spec.name == param.name && spec.secret),
        })
        .collect()
}

/// Whether a validator detail message describes an invalid SCHEMA (as opposed to
/// a value that failed an otherwise-valid schema). The agent-run validator emits
/// value-failure messages prefixed `output did not satisfy output_schema`, and
/// schema-shape messages prefixed `output_schema`, so the distinction is stable.
fn is_schema_invalid_detail(detail: &str) -> bool {
    detail.starts_with("output_schema")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn spec(name: &str, schema: serde_json::Value, required: bool) -> WorkflowParamSpec {
        WorkflowParamSpec {
            name: SmolStr::new(name),
            schema,
            required,
            default: None,
            secret: false,
            doc: None,
        }
    }

    fn supplied(pairs: &[(&str, serde_json::Value)]) -> serde_json::Map<String, serde_json::Value> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect()
    }

    #[test]
    fn resolves_required_and_fills_defaults_in_name_order() {
        let specs = vec![
            spec("target", json!({"type": "string"}), true),
            WorkflowParamSpec {
                default: Some(json!(3)),
                required: false,
                ..spec("count", json!({"type": "integer"}), false)
            },
        ];
        let rows =
            resolve_and_validate_params(&specs, &supplied(&[("target", json!("main"))])).unwrap();
        // Sorted by name: count then target.
        assert_eq!(
            rows,
            vec![
                InvocationParam {
                    name: SmolStr::new("count"),
                    value: json!(3)
                },
                InvocationParam {
                    name: SmolStr::new("target"),
                    value: json!("main")
                },
            ]
        );
    }

    #[test]
    fn supply_order_does_not_change_rows() {
        let specs = vec![
            spec("a", json!({"type": "string"}), true),
            spec("b", json!({"type": "string"}), true),
        ];
        let one =
            resolve_and_validate_params(&specs, &supplied(&[("a", json!("x")), ("b", json!("y"))]))
                .unwrap();
        let two =
            resolve_and_validate_params(&specs, &supplied(&[("b", json!("y")), ("a", json!("x"))]))
                .unwrap();
        assert_eq!(one, two, "resolved rows are canonical regardless of order");
    }

    #[test]
    fn unknown_key_is_refused() {
        let specs = vec![spec("target", json!({"type": "string"}), true)];
        let err = resolve_and_validate_params(
            &specs,
            &supplied(&[("target", json!("x")), ("nope", json!(1))]),
        )
        .unwrap_err();
        assert_eq!(err.code(), "param.unknown_key");
    }

    #[test]
    fn missing_required_is_refused() {
        let specs = vec![spec("target", json!({"type": "string"}), true)];
        let err = resolve_and_validate_params(&specs, &supplied(&[])).unwrap_err();
        assert_eq!(err.code(), "param.missing_required");
    }

    #[test]
    fn type_mismatch_is_refused() {
        let specs = vec![spec("count", json!({"type": "integer"}), true)];
        let err = resolve_and_validate_params(&specs, &supplied(&[("count", json!("nope"))]))
            .unwrap_err();
        assert_eq!(err.code(), "param.type_mismatch");
    }

    #[test]
    fn enum_and_pattern_constraints_enforced() {
        let specs = vec![
            spec(
                "mode",
                json!({"type": "string", "enum": ["fast", "slow"]}),
                true,
            ),
            spec(
                "note",
                json!({"type": "string", "pattern": "^[a-z]+$"}),
                true,
            ),
        ];
        let err = resolve_and_validate_params(
            &specs,
            &supplied(&[("mode", json!("turbo")), ("note", json!("ok"))]),
        )
        .unwrap_err();
        assert_eq!(err.code(), "param.type_mismatch");
    }

    /// A pattern violation on its own (no enum arm shadowing it) is refused
    /// through the resolver with the stable code.
    #[test]
    fn pattern_violation_is_refused_through_the_resolver() {
        let specs = vec![spec(
            "note",
            json!({"type": "string", "pattern": "^[a-z][a-z-]*$"}),
            true,
        )];
        let err = resolve_and_validate_params(&specs, &supplied(&[("note", json!("Nope Caps"))]))
            .unwrap_err();
        assert_eq!(err.code(), "param.type_mismatch");
        assert!(err.to_string().contains("pattern"), "{err}");
    }

    /// A maxLength violation on its own is refused through the resolver.
    #[test]
    fn max_length_violation_is_refused_through_the_resolver() {
        let specs = vec![spec(
            "note",
            json!({"type": "string", "maxLength": 4}),
            true,
        )];
        let err = resolve_and_validate_params(&specs, &supplied(&[("note", json!("toolong"))]))
            .unwrap_err();
        assert_eq!(err.code(), "param.type_mismatch");
        assert!(err.to_string().contains("length"), "{err}");
    }

    /// MAJOR-1 regression: a mistyped CONSTRAINED SECRET must not echo the
    /// supplied value in the refusal — the shared validator's messages embed the
    /// offending value (enum/pattern/bounds), so the resolver withholds the
    /// detail for a secret param.
    #[test]
    fn secret_type_mismatch_withholds_the_value() {
        let sentinel = "SENTINEL_SECRET_VALUE_MUST_NOT_LEAK";
        let specs = vec![WorkflowParamSpec {
            secret: true,
            ..spec(
                "api_token",
                json!({"type": "string", "pattern": "^tok-[a-z0-9]+$"}),
                true,
            )
        }];
        let err = resolve_and_validate_params(&specs, &supplied(&[("api_token", json!(sentinel))]))
            .unwrap_err();
        assert_eq!(err.code(), "param.type_mismatch");
        let rendered = err.to_string();
        assert!(
            !rendered.contains(sentinel),
            "the refusal must not echo the secret value: {rendered}"
        );
        assert!(rendered.contains("api_token"), "{rendered}");
        assert!(rendered.contains("withheld"), "{rendered}");
    }

    #[test]
    fn secret_param_must_be_supplied() {
        let specs = vec![WorkflowParamSpec {
            secret: true,
            required: true,
            ..spec("api_token", json!({"type": "string"}), true)
        }];
        let err = resolve_and_validate_params(&specs, &supplied(&[])).unwrap_err();
        assert_eq!(err.code(), "param.secret_required");
        // Supplied → resolves.
        let rows =
            resolve_and_validate_params(&specs, &supplied(&[("api_token", json!("s3cr3t"))]))
                .unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn too_many_supplied_is_refused() {
        let specs: Vec<WorkflowParamSpec> = (0..MAX_INVOCATION_PARAMS)
            .map(|i| spec(&format!("p{i}"), json!({"type": "string"}), false))
            .collect();
        let big: serde_json::Map<String, serde_json::Value> = (0..=MAX_INVOCATION_PARAMS)
            .map(|i| (format!("q{i}"), json!("x")))
            .collect();
        let err = resolve_and_validate_params(&specs, &big).unwrap_err();
        assert_eq!(err.code(), "param.too_many");
    }

    #[test]
    fn value_too_large_is_refused() {
        let specs = vec![spec("blob", json!({"type": "string"}), true)];
        let huge = "x".repeat(MAX_PARAM_VALUE_BYTES + 10);
        let err =
            resolve_and_validate_params(&specs, &supplied(&[("blob", json!(huge))])).unwrap_err();
        assert_eq!(err.code(), "param.value_too_large");
    }

    #[test]
    fn param_error_codes_are_stable() {
        // The seven stable codes, pinned so a rename is a conscious wire break.
        assert_eq!(
            ParamError::UnknownKey { name: "x".into() }.code(),
            "param.unknown_key"
        );
        assert_eq!(
            ParamError::MissingRequired { name: "x".into() }.code(),
            "param.missing_required"
        );
        assert_eq!(
            ParamError::TypeMismatch {
                name: "x".into(),
                detail: String::new()
            }
            .code(),
            "param.type_mismatch"
        );
        assert_eq!(
            ParamError::SchemaInvalid {
                name: "x".into(),
                detail: String::new()
            }
            .code(),
            "param.schema_invalid"
        );
        assert_eq!(
            ParamError::TooMany { count: 0, max: 0 }.code(),
            "param.too_many"
        );
        assert_eq!(
            ParamError::ValueTooLarge {
                name: "x".into(),
                bytes: 0,
                max: 0
            }
            .code(),
            "param.value_too_large"
        );
        assert_eq!(
            ParamError::SecretRequired { name: "x".into() }.code(),
            "param.secret_required"
        );
    }
}
