//! Native contract + graph DSL — argument decode + section-assembly helpers.
//!
//! Free helpers shared by the contract/graph builtins, a pure relocation out of
//! the former single `dsl` module. Cross-module callers live in
//! [`super::contract_globals`] and [`super::graph_globals`]; helpers used only
//! within this module stay private.

use serde_json::Value as JsonValue;
use smol_str::SmolStr;
use starlark::values::dict::DictRef;
use starlark::values::list_or_tuple::UnpackListOrTuple;
use starlark::values::{UnpackValue, Value};

use kata_types::agent_run::validate_param_value_against_schema;
use kata_types::params::WorkflowParamSpec;

use super::builder::{self, WorkflowExtensionsJson};
use super::schema::{DslType, Primitive, PrimitiveConstraints, param_type_schema};
use super::values::{
    BoundValue, ChannelValue, Contract, EnumType, Field, HumanRequestValue, ListType,
    MemorySelectorValue, MemoryWritebackValue, PrimitiveType, Role, SandboxProfileValue, StageRef,
    ValidationCriterionValue, VariantType, WorkflowPatternValue,
};

/// Decode a `ty` argument accepted by `field` / `list_of` / `variant` into a
/// [`DslType`].
///
/// Accepted forms: a primitive spelling string (`"string"`, `"number"`,
/// `"integer"`, `"bool"`, `"null"` — constraint-free), a constrained primitive
/// marker from `number()`/`integer()`/`string()`, an [`EnumType`], a
/// [`ListType`], a [`VariantType`], or a nested [`Contract`].
pub(super) fn decode_type(value: Value<'_>) -> starlark::Result<DslType> {
    if let Some(spelling) = value.unpack_str() {
        return Primitive::parse(spelling)
            .map(|primitive| DslType::Primitive(primitive, PrimitiveConstraints::default()))
            .ok_or_else(|| {
                starlark::Error::new_other(anyhow::anyhow!(
                    "unknown primitive type {spelling:?}; expected one of \
                 \"string\", \"number\", \"integer\", \"bool\", \"null\", or a \
                 marker from number()/integer()/string()/enum()/list_of()/variant()/contract()"
                ))
            });
    }
    if let Some(primitive_ty) = PrimitiveType::from_value(value) {
        return Ok(DslType::Primitive(
            primitive_ty.primitive,
            primitive_ty.constraints.clone(),
        ));
    }
    if let Some(enum_ty) = EnumType::from_value(value) {
        return Ok(DslType::Enum(enum_ty.variants.clone()));
    }
    if let Some(list_ty) = ListType::from_value(value) {
        return Ok(DslType::List(Box::new(list_ty.element.clone())));
    }
    if let Some(variant_ty) = VariantType::from_value(value) {
        return Ok(DslType::Variant(variant_ty.arms.clone()));
    }
    if let Some(contract) = Contract::from_value(value) {
        return Ok(DslType::Object(contract.shape.clone()));
    }
    Err(starlark::Error::new_other(anyhow::anyhow!(
        "expected a contract field type: a primitive string, or a value from \
         number()/integer()/string()/enum()/list_of()/variant()/contract(); got a {}",
        value.get_type()
    )))
}

/// Decode the optional `min=`/`max=` kwargs of `number()`/`integer()` into
/// numeric [`PrimitiveConstraints`].
///
/// Each bound accepts a Starlark int or float (routed through `to_json_value()`
/// like `cost_bound(usd=..)`); any other type is a clean DSL error. The
/// semantic `min <= max` check is enforced at lowering
/// (`schema::primitive_schema`), alongside the JSON emission, so the rule lives
/// in one place shared with the schema invariant.
pub(super) fn decode_numeric_constraints(
    min: Option<Value<'_>>,
    max: Option<Value<'_>>,
    owner: &str,
) -> starlark::Result<PrimitiveConstraints> {
    Ok(PrimitiveConstraints {
        minimum: decode_opt_number(min, owner, "min")?,
        maximum: decode_opt_number(max, owner, "max")?,
        ..PrimitiveConstraints::default()
    })
}

/// Decode an optional numeric kwarg (int or float) into a [`serde_json::Number`],
/// preserving the author's exact literal for the lowered `minimum`/`maximum`.
fn decode_opt_number(
    value: Option<Value<'_>>,
    owner: &str,
    field: &str,
) -> starlark::Result<Option<serde_json::Number>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let type_err = || {
        starlark::Error::new_other(anyhow::anyhow!(
            "{owner} {field}= must be a number; got a {}",
            value.get_type()
        ))
    };
    match value.to_json_value().map_err(|_| type_err())? {
        JsonValue::Number(number) => Ok(Some(number)),
        _ => Err(type_err()),
    }
}

/// Decode the optional `pattern=`/`min_length=`/`max_length=` kwargs of
/// `string()` into string [`PrimitiveConstraints`].
///
/// `-1` is the unset sentinel for the length bounds (matching the
/// extension-count kwargs); a value below `-1` is a clean DSL error. The
/// pattern's regex-compilability, the `min_length <= max_length` ordering, and
/// the length ceiling are enforced at lowering (`schema::primitive_schema`).
pub(super) fn decode_string_constraints(
    pattern: &str,
    min_length: i64,
    max_length: i64,
    owner: &str,
) -> starlark::Result<PrimitiveConstraints> {
    Ok(PrimitiveConstraints {
        pattern: (!pattern.is_empty()).then(|| pattern.to_owned()),
        min_length: decode_opt_length(min_length, owner, "min_length")?,
        max_length: decode_opt_length(max_length, owner, "max_length")?,
        ..PrimitiveConstraints::default()
    })
}

/// Decode an optional length kwarg: `-1` (unset) → `None`; `>= 0` → `Some`; a
/// value below `-1` is a clean DSL error.
fn decode_opt_length(value: i64, owner: &str, field: &str) -> starlark::Result<Option<u64>> {
    match value {
        -1 => Ok(None),
        n if n >= 0 => Ok(Some(
            u64::try_from(n).expect("a non-negative i64 always fits in u64"),
        )),
        n => Err(starlark::Error::new_other(anyhow::anyhow!(
            "{owner} {field}= must be >= 0 (or omitted to leave it unset); got {n}"
        ))),
    }
}

/// Decode a `depends_on` / `root` element into the referenced stage id.
///
/// Accepts a [`StageRef`] (the value `stage(..)` returns). A bare string is
/// also accepted as an id reference for ergonomic forward references, though
/// the typed `StageRef` is the idiomatic form.
pub(super) fn decode_stage_ref(value: Value<'_>) -> starlark::Result<String> {
    if let Some(stage_ref) = StageRef::from_value(value) {
        return Ok(stage_ref.id.clone());
    }
    if let Some(id) = value.unpack_str() {
        return Ok(id.to_owned());
    }
    Err(starlark::Error::new_other(anyhow::anyhow!(
        "expected a stage reference from stage(..) (or a stage-id string); got a {}",
        value.get_type()
    )))
}

/// Decode an optional `produces=` / `consumes=` argument into the contract's
/// name and generated JSON schema.
///
/// `None` (the unset default) yields `Ok(None)`. A [`Contract`] value yields
/// `Ok(Some((name, schema)))` carrying the contract's declared name (for the
/// type-checker's error messages) and its already-generated, validator-shaped
/// schema. Any other type is a clean Starlark error — these arguments accept only
/// a value returned by `contract(..)`.
pub(super) fn decode_contract_arg(
    value: Option<Value<'_>>,
    arg_name: &str,
) -> starlark::Result<Option<(String, JsonValue)>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let Some(contract) = Contract::from_value(value) else {
        return Err(starlark::Error::new_other(anyhow::anyhow!(
            "stage() {arg_name}= must be a contract(..) value; got a {}",
            value.get_type()
        )));
    };
    Ok(Some((contract.shape.name.clone(), contract.schema.clone())))
}

/// Decode the `cache_policy=` string kwarg into the AUTHORED
/// cache decision, then project it onto the durable
/// [`kata_types::cache::CachePolicy`].
///
/// # Not `serde_json::from_value`
///
/// Reading the spelling straight through `CachePolicy`'s serde
/// `rename_all = "snake_case"` would centralize the WRONG thing: serde's domain
/// is the WIRE, which cannot tell `""` (the kwarg omitted) from `"disabled"` (an
/// explicit exemption), so the authored intent would be destroyed at the
/// earliest possible point and every downstream gate would have to read an
/// absence as a decision.
///
/// The authority is
/// [`AuthoredCachePolicy::from_spelling`](kata_types::cache::AuthoredCachePolicy::from_spelling),
/// which is ONE place and knows all three states. Its
/// [`collapse`](kata_types::cache::AuthoredCachePolicy::collapse) is TOTAL
/// and LOSSLESS — `""` reaches
/// [`CachePolicy::Omitted`](kata_types::cache::CachePolicy::Omitted) and stays
/// there, so the authored intent is not destroyed at any point on the
/// path from the kwarg to the durable program.
///
/// # REFUSED vs CLAIMED
///
/// * ACCEPTS `""`, `"disabled"`, `"no_cache"`, `"model_reuse"`,
///   `"content_cache"`.
/// * REFUSES everything else, and refuses the RESERVED tags
///   ([`AuthoredCachePolicy::RESERVED_SPELLINGS`](kata_types::cache::AuthoredCachePolicy::RESERVED_SPELLINGS))
///   with their own message, so an author who types `"omitted"` is told that
///   omission is spelled by omitting rather than being handed a value that will
///   mean something different after the durable variant lands.
/// * The DSL catalog's `cache_policy` domain (`super::catalog`) is built from
///   `CachePolicy::variants()` and CLAIMS three spellings while this accepts
///   five. The gap is `""` (which the catalog cannot express — it is the absence
///   of the kwarg) and `"no_cache"` (a synonym for a value already in the
///   domain). Neither is exploitable: nothing decodable through them is
///   undecodable through an advertised spelling. But a completion surface built
///   on the catalog will not offer `"no_cache"`, and `catalog.rs`'s own
///   decode-roundtrip guard claims *"a spelling the catalog advertises is one
///   the evaluator accepts, and vice versa"* — the *vice versa* half is
///   false by exactly that one spelling. Closing it is a one-line addition to
///   the catalog domain.
pub(super) fn decode_cache_policy(
    spelling: &str,
) -> starlark::Result<kata_types::cache::CachePolicy> {
    use kata_types::cache::AuthoredCachePolicy;
    if AuthoredCachePolicy::is_reserved_spelling(spelling) {
        return Err(starlark::Error::new_other(anyhow::anyhow!(
            "stage() cache_policy={spelling:?} is RESERVED and cannot be authored: it is the \
             spelling of \"the author said nothing\", which is written by leaving cache_policy= \
             off the stage entirely. To opt a stage OUT of caching, write \
             cache_policy=\"no_cache\""
        )));
    }
    AuthoredCachePolicy::from_spelling(spelling)
        .map(AuthoredCachePolicy::collapse)
        .ok_or_else(|| {
            starlark::Error::new_other(anyhow::anyhow!(
                "stage() cache_policy= must be one of {}; got {spelling:?}. Omit the kwarg \
                 entirely to let kata decide from the stage's derived execution class",
                AuthoredCachePolicy::authorable_spellings()
                    .iter()
                    .map(|tag| format!("{tag:?}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })
}

/// Decode the `progress_visibility=` string kwarg into the
/// typed [`kata_types::ProgressVisibility`] with its canonical serde spelling.
///
/// Its serde `rename_all = "snake_case"` accepts `"off"`, `"summary"`, and
/// `"full"`. An empty string (unset) yields `default()` (`Off`).
pub(super) fn decode_progress_visibility(
    spelling: &str,
) -> starlark::Result<kata_types::ProgressVisibility> {
    if spelling.is_empty() {
        return Ok(kata_types::ProgressVisibility::default());
    }
    serde_json::from_value(JsonValue::String(spelling.to_owned())).map_err(|_| {
        starlark::Error::new_other(anyhow::anyhow!(
            "stage() progress_visibility= must be one of \"off\", \"summary\", \"full\"; \
             got {spelling:?}"
        ))
    })
}

/// Decode the `exit_policy=` string kwarg into the typed
/// [`kata_types::workflow::ShellExitPolicy`] with its canonical serde spelling.
///
/// Its serde `rename_all = "snake_case"` accepts `"content"` and
/// `"zero_success"`. An empty string (unset) yields `default()`, which is
/// `ZeroSuccess` — so a stage that writes nothing TERMINALIZES on a nonzero
/// exit, and `"content"` is the spelling that asks for the swallow. Routing the non-empty spelling
/// through `serde_json::from_value` reuses the exact same typed decoder, so accepted spellings and
/// rejection stay centralized on the type.
pub(super) fn decode_exit_policy(
    spelling: &str,
) -> starlark::Result<kata_types::workflow::ShellExitPolicy> {
    if spelling.is_empty() {
        return Ok(kata_types::workflow::ShellExitPolicy::default());
    }
    serde_json::from_value(JsonValue::String(spelling.to_owned())).map_err(|_| {
        starlark::Error::new_other(anyhow::anyhow!(
            "stage() exit_policy= must be one of \"content\", \"zero_success\"; got {spelling:?}. \
             \"zero_success\" (the default) fails the stage on a nonzero exit; \
             \"content\" completes the stage and records the code at the output's root `exit_code`"
        ))
    })
}

/// Decode the flat `outputs={name: \"type-label\"}` dict into
/// a `Vec<(name, ty)>` sorted by name.
///
/// The lowered `StageDefinition::outputs` is an *ordered* `Vec` that folds into
/// the normalized-definition hash, so this sorts by
/// output name (a Starlark dict otherwise preserves insertion order). Duplicate
/// names cannot occur (Starlark dict keys are unique). Both keys and values must
/// be strings.
pub(super) fn decode_outputs(outputs: DictRef<'_>) -> starlark::Result<Vec<(String, String)>> {
    let mut decoded = Vec::with_capacity(outputs.len());
    for (key, value) in outputs.iter() {
        let name = key.unpack_str().ok_or_else(|| {
            starlark::Error::new_other(anyhow::anyhow!(
                "stage() outputs keys must be strings (output names); got a {}",
                key.get_type()
            ))
        })?;
        let ty = value.unpack_str().ok_or_else(|| {
            starlark::Error::new_other(anyhow::anyhow!(
                "stage() outputs values must be strings (type labels); output {name:?} got a {}",
                value.get_type()
            ))
        })?;
        decoded.push((name.to_owned(), ty.to_owned()));
    }
    // Use stable key order so the lowered output Vec — and therefore the
    // normalized-definition hash — is deterministic.
    decoded.sort_by(|(a, _), (b, _)| a.cmp(b));
    Ok(decoded)
}

/// Decode the `workflow(params={..})` dict into typed
/// [`WorkflowParamSpec`]s (canonical name order).
///
/// Each value may be:
/// * a `field(ty, required=.., default=.., secret=.., doc=..)` value — a typed
///   param declaration; or
/// * a bare type spelling / marker (`"string"`, `integer(min=..)`,
///   `enum("a","b")`, …) — the flat `{name: "type"}` shape, promoted to a
///   REQUIRED param of that type with no default and no secret marker.
///
/// Rules enforced here (author-time, fail-closed):
/// * the type node must lower to a validator-accepted schema;
/// * a `default=` value must satisfy the param's declared type;
/// * a `default=` makes the param OPTIONAL (a default is the value used when the
///   param is omitted), so an EXPLICIT `required=True` beside one is a
///   contradiction and is REFUSED rather than silently coerced to optional;
/// * a `secret=True` param must NOT declare a `default=` and is always required
///   (a plaintext default secret must never live in source; a secret must be
///   supplied at every invocation), so an EXPLICIT `required=False` beside one
///   is likewise REFUSED rather than silently coerced to required.
pub(super) fn decode_params(params: DictRef<'_>) -> starlark::Result<Vec<WorkflowParamSpec>> {
    // Bound the DECLARED param count at load time (mirroring the resolver's
    // submit-time bound), so an over-declared pack refuses at `workflows check`
    // rather than at its first submission.
    if params.len() > kata_types::params::MAX_INVOCATION_PARAMS {
        return Err(starlark::Error::new_other(anyhow::anyhow!(
            "workflow() declares {} params; maximum is {}",
            params.len(),
            kata_types::params::MAX_INVOCATION_PARAMS
        )));
    }
    let mut specs = Vec::with_capacity(params.len());
    for (key, value) in params.iter() {
        let name = key.unpack_str().ok_or_else(|| {
            starlark::Error::new_other(anyhow::anyhow!(
                "workflow() params keys must be strings (param names); got a {}",
                key.get_type()
            ))
        })?;
        let spec = if let Some(field) = Field::from_value(value) {
            decode_param_field(name, field)?
        } else {
            // Flat `{name: "type"}` (or a bare marker): a required param.
            let ty = decode_type(value)?;
            let schema = param_type_schema(&ty).map_err(|err| {
                starlark::Error::new_other(anyhow::anyhow!("workflow() param {name:?} type: {err}"))
            })?;
            WorkflowParamSpec {
                name: SmolStr::new(name),
                schema,
                required: true,
                default: None,
                secret: false,
                doc: None,
            }
        };
        specs.push(spec);
    }
    // Canonical name order so the lowered specs — and therefore the program hash —
    // are deterministic regardless of authored dict order.
    specs.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(specs)
}

/// Decode a `{name: value}` dict of AUTHORED CONSTANT param values into a
/// raw JSON object.
///
/// Used by `schedule(params={..})` and `subworkflow(params={..})`, where the
/// author supplies concrete VALUES (not typed declarations); those values are
/// resolved + validated against the TARGET pack's declared param contract at
/// submit/fire time, so this only converts the Starlark values to JSON. Keys must
/// be strings; each value must be JSON-convertible.
pub(super) fn decode_param_constants(
    params: &DictRef<'_>,
    owner: &str,
) -> starlark::Result<serde_json::Map<String, JsonValue>> {
    let mut out = serde_json::Map::with_capacity(params.len());
    for (key, value) in params.iter() {
        let name = key.unpack_str().ok_or_else(|| {
            starlark::Error::new_other(anyhow::anyhow!(
                "{owner} params keys must be strings (param names); got a {}",
                key.get_type()
            ))
        })?;
        let json = value.to_json_value().map_err(|err| {
            starlark::Error::new_other(anyhow::anyhow!(
                "{owner} params[{name:?}] must be a JSON value: {err}"
            ))
        })?;
        out.insert(name.to_owned(), json);
    }
    Ok(out)
}

/// Build one [`WorkflowParamSpec`] from a typed `field(..)` param declaration.
fn decode_param_field(name: &str, field: &Field) -> starlark::Result<WorkflowParamSpec> {
    let schema = param_type_schema(&field.ty).map_err(|err| {
        starlark::Error::new_other(anyhow::anyhow!("workflow() param {name:?} type: {err}"))
    })?;
    if field.secret && field.default.is_some() {
        return Err(starlark::Error::new_other(anyhow::anyhow!(
            "workflow() param {name:?} is secret=True and also declares default=; a secret param \
             must be supplied at every invocation and must never carry a plaintext default"
        )));
    }
    // The two contradictions `field()`'s own doc promises are rejected at author
    // time. Both turn on an EXPLICIT `required=` — an unspelled one carries the
    // `True` default, which is what `field(ty, default=..)` and
    // `field(ty, secret=True)` (the ordinary spellings) rely on. `Field` holds
    // `Option<bool>` so an explicit spelling is distinguishable from that default;
    // a plain `bool` would leave neither rejection able to fire, and an explicit
    // `required=True` would be SILENTLY overwritten to optional a few lines below —
    // the opposite of what the author wrote, with no diagnostic at load, at
    // `workflows check`, or at verify. (`execution_program::verify`'s
    // `param_required_with_default` names this rule but inspects the
    // ALREADY-COERCED spec, so it can never fire for a DSL-authored pack.)
    if field.default.is_some() && field.required == Some(true) {
        return Err(starlark::Error::new_other(anyhow::anyhow!(
            "workflow() param {name:?} declares both required=True and default=; a default IS \
             the value used when the param is omitted, so a defaulted param is optional. Drop \
             `required=True` to keep the default, or drop `default=` to keep the param required"
        )));
    }
    if field.secret && field.required == Some(false) {
        return Err(starlark::Error::new_other(anyhow::anyhow!(
            "workflow() param {name:?} declares both secret=True and required=False; a secret \
             param must be supplied at every invocation (it can carry no default to fall back \
             on). Drop `required=False`, or drop `secret=True` if the value is not a secret"
        )));
    }
    // A default makes the param optional (it is the value used when omitted); a
    // secret is always required and never defaulted.
    let (required, default) = if field.secret {
        (true, None)
    } else if let Some(default) = &field.default {
        (false, Some(default.clone()))
    } else {
        (field.required.unwrap_or(true), None)
    };
    if let Some(default) = &default {
        validate_param_value_against_schema(default, &schema).map_err(|detail| {
            starlark::Error::new_other(anyhow::anyhow!(
                "workflow() param {name:?} default= does not satisfy its declared type: {detail}"
            ))
        })?;
    }
    Ok(WorkflowParamSpec {
        name: SmolStr::new(name),
        schema,
        required,
        default,
        secret: field.secret,
        doc: field.doc.clone(),
    })
}

/// Decode an optional `cost_budget=` dict kwarg into the raw
/// `serde_json::Value` the shared budget normalizer consumes.
///
/// `parser::normalize_budget_value` deserializes the
/// `{mode: "unlimited"|"warn"|"halt", limit_usd: <float>}` shape). To match that
/// normalized JSON shape, this converts the Starlark dict value via
/// `Value::to_json_value()`, and the builder feeds the result to
/// `normalize_budget_value` at
/// lowering. `None` (unset) leaves the budget at its `Unlimited` default. The
/// budget *shape* remains mode plus `limit_usd`;
/// validation of mode spelling / limit_usd is deferred to the shared normalizer.
pub(super) fn decode_cost_budget(
    value: Option<Value<'_>>,
    owner: &str,
) -> starlark::Result<Option<JsonValue>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if DictRef::from_value(value).is_none() {
        return Err(starlark::Error::new_other(anyhow::anyhow!(
            "{owner} cost_budget= must be a dict of the form \
             {{\"mode\": {}, \"limit_usd\": <number>}}; got a {}",
            <kata_types::BudgetMode as strum::VariantArray>::VARIANTS
                .iter()
                .map(|mode| format!("{:?}", mode.label()))
                .collect::<Vec<_>>()
                .join("|"),
            value.get_type()
        )));
    }
    let json = value.to_json_value().map_err(|err| {
        starlark::Error::new_other(anyhow::anyhow!("{owner} cost_budget=: {err}"))
    })?;
    Ok(Some(json))
}

/// Decode a `cost_bound(usd)` numeric argument into an `f64`.
///
/// Accepts a Starlark `float` (`5.0`) or `int` (`5`) for ergonomics — matching
/// how `cost_budget(limit_usd=..)` tolerates either — by routing through
/// `Value::to_json_value()` and reading the resulting JSON number. Any other
/// type (or a non-numeric value) is a clean Starlark error. Value-range
/// validation (`> 0`, converts to >= 1 micro-USD) is left to the caller's
/// `Bound::cost_usd`.
pub(super) fn decode_usd_amount(value: Value<'_>, owner: &str) -> starlark::Result<f64> {
    let json = value.to_json_value().map_err(|_| {
        starlark::Error::new_other(anyhow::anyhow!(
            "{owner} usd must be a number; got a {}",
            value.get_type()
        ))
    })?;
    match json {
        JsonValue::Number(n) => n.as_f64().ok_or_else(|| {
            starlark::Error::new_other(anyhow::anyhow!("{owner} usd is not a finite number"))
        }),
        other => Err(starlark::Error::new_other(anyhow::anyhow!(
            "{owner} usd must be a number; got {other}"
        ))),
    }
}

/// Decode a `workflow(bounds=[..])` list into a
/// `Vec<Bound>` for the builder to validate (per-kind-uniqueness) and lower.
///
/// Each element must be a [`BoundValue`] (from `time_bound(..)` / `cost_bound(..)` /
/// `token_bound(..)`);
/// any other type is a clean Starlark error. The carried [`Bound`] is already
/// value-validated by its constructor; per-kind-uniqueness + canonical ordering
/// is enforced at the `workflow()` drain / `loop()` call via
/// `kata_types::bound::validate_bounds`.
///
/// `owner` is the operator-facing scope label (`"workflow()"` / `"loop()"`) so
/// a misused entry reads clearly. Both the workflow-scope and loop-scope
/// `bounds=` surfaces decode through here.
///
/// The decoded bounds enter checked IR and the runner enforces them as durable
/// cost/time/token walk-aways at workflow or loop scope.
pub(super) fn decode_bounds(
    bounds: &[Value<'_>],
    owner: &str,
) -> starlark::Result<Vec<kata_types::bound::Bound>> {
    bounds
        .iter()
        .map(|value| {
            BoundValue::from_value(*value)
                .map(|bv| bv.bound)
                .ok_or_else(|| {
                    starlark::Error::new_other(anyhow::anyhow!(
                        "{owner} bounds= entries must be time_bound(..)/cost_bound(..)/\
                         token_bound(..) values; got a {}",
                        value.get_type()
                    ))
                })
        })
        .collect()
}

/// Decode an optional
/// `loop(gate_verdict={..})` dict into a validated
/// [`kata_types::review_loop::LoopVerdictConfig`].
///
/// Shape: `{"field": "<verdict field>", "approve": [..], "refine": [..],
/// "block": [..]}`. `field` is the reviewer-envelope field carrying the
/// verdict (a bare enum string OR a `variant` object — the runtime reads
/// either). The three lists are the tag-sets routing to Approved / next
/// iteration / Blocked. `None` (kwarg omitted) ⇒ the default vocabulary.
///
/// Validation (non-empty field, non-empty + pairwise-disjoint tag-sets) is
/// delegated to [`kata_types::review_loop::LoopVerdictConfig::new`] so Starlark
/// and programmatic checked definitions share one rule; unknown keys and wrong value types
/// are clean Starlark errors here.
pub(super) fn decode_gate_verdict(
    gate_verdict: Option<&DictRef<'_>>,
) -> starlark::Result<Option<kata_types::review_loop::LoopVerdictConfig>> {
    let Some(dict) = gate_verdict else {
        return Ok(None);
    };
    let mut field: Option<SmolStr> = None;
    let mut approve: Option<Vec<SmolStr>> = None;
    let mut refine: Option<Vec<SmolStr>> = None;
    let mut block: Option<Vec<SmolStr>> = None;
    for (key, value) in dict.iter() {
        let key = key.unpack_str().ok_or_else(|| {
            starlark::Error::new_other(anyhow::anyhow!(
                "loop() gate_verdict keys must be strings; got a {}",
                key.get_type()
            ))
        })?;
        match key {
            "field" => {
                let s = value.unpack_str().ok_or_else(|| {
                    starlark::Error::new_other(anyhow::anyhow!(
                        "loop() gate_verdict \"field\" must be a string; got a {}",
                        value.get_type()
                    ))
                })?;
                field = Some(SmolStr::new(s));
            }
            "approve" | "refine" | "block" => {
                let tags = decode_verdict_tag_set(key, value)?;
                match key {
                    "approve" => approve = Some(tags),
                    "refine" => refine = Some(tags),
                    _ => block = Some(tags),
                }
            }
            other => {
                return Err(starlark::Error::new_other(anyhow::anyhow!(
                    "loop() gate_verdict has unknown key {other:?}; expected \"field\", \
                     \"approve\", \"refine\", \"block\""
                )));
            }
        }
    }
    let field = field.ok_or_else(|| {
        starlark::Error::new_other(anyhow::anyhow!(
            "loop() gate_verdict must declare a \"field\" string"
        ))
    })?;
    let missing = |role: &str| {
        starlark::Error::new_other(anyhow::anyhow!(
            "loop() gate_verdict must declare a {role:?} tag list"
        ))
    };
    let config = kata_types::review_loop::LoopVerdictConfig::new(
        field,
        approve.ok_or_else(|| missing("approve"))?,
        refine.ok_or_else(|| missing("refine"))?,
        block.ok_or_else(|| missing("block"))?,
    )
    .map_err(|err| {
        starlark::Error::new_other(anyhow::anyhow!("loop() gate_verdict invalid: {err}"))
    })?;
    Ok(Some(config))
}

/// Decode one `loop(gate_verdict={..})` tag-set value (the value under
/// `approve`/`refine`/`block`) into a `Vec<SmolStr>`. Accepts a list or tuple
/// of strings; a bare string is rejected to keep the author intent (a set)
/// explicit. Emptiness + disjointness are validated by
/// [`kata_types::review_loop::LoopVerdictConfig::new`].
fn decode_verdict_tag_set(role: &str, value: Value<'_>) -> starlark::Result<Vec<SmolStr>> {
    let tags = UnpackListOrTuple::<String>::unpack_value(value)?.ok_or_else(|| {
        starlark::Error::new_other(anyhow::anyhow!(
            "loop() gate_verdict {role:?} must be a list of strings; got a {}",
            value.get_type()
        ))
    })?;
    Ok(tags.items.into_iter().map(SmolStr::new).collect())
}

/// Decode a `topology(root=..)` / element of
/// `topology(workers=..)` / `topology(reviewers=..)` argument into the
/// normalized role JSON deserialized into
/// [`kata_types::workflow::AgentRolePolicy`].
///
/// Only a [`Role`] value (from `role(..)`) is accepted; any other type is a
/// clean Starlark error. The carried JSON uses the normalized helper shape and
/// decodes through one typed serde path.
pub(super) fn decode_role(value: Value<'_>, field: &str) -> starlark::Result<JsonValue> {
    let Some(role) = Role::from_value(value) else {
        return Err(starlark::Error::new_other(anyhow::anyhow!(
            "topology() {field}= must be a role(..) value; got a {}",
            value.get_type()
        )));
    };
    Ok(role.json.clone())
}

/// Decode an optional positive `max_concurrency=` /
/// `fanout_limit=` integer kwarg.
///
/// Omitting the kwarg yields `None`. A passed value must be `>= 0`; any negative,
/// including `-1`, is a clear Starlark authoring error (there is no `-1`
/// sentinel on this builtin).
pub(super) fn decode_optional_u32(
    value: Option<i64>,
    field: &str,
) -> starlark::Result<Option<u32>> {
    match value {
        None => Ok(None),
        Some(n) if n >= 0 => u32::try_from(n).map(Some).map_err(|_| {
            starlark::Error::new_other(anyhow::anyhow!(
                "topology() {field}= is out of range for a 32-bit count; got {n}"
            ))
        }),
        Some(n) => Err(starlark::Error::new_other(anyhow::anyhow!(
            "topology() {field}= must be >= 0 (or omitted to leave it unset); got {n}"
        ))),
    }
}

/// Decode the `sandbox=` argument of `stage()` into the
/// JSON shape the shared `sandbox_ref_from_json` decoder consumes.
///
/// A bare string names a workflow profile (`SandboxRef::Named`); an inline
/// `sandbox_profile(..)` value lowers inline (`SandboxRef::Inline`). The carried
/// JSON — a string or the profile object — is routed through
/// `sandbox_ref_from_json` at lowering, the single shared lowering for the
/// native graph DSL's stage `sandbox` field.
pub(super) fn decode_sandbox_arg(value: Option<Value<'_>>) -> starlark::Result<Option<JsonValue>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if let Some(name) = value.unpack_str() {
        return Ok(Some(JsonValue::String(name.to_owned())));
    }
    if let Some(profile) = SandboxProfileValue::from_value(value) {
        return Ok(Some(profile.json.clone()));
    }
    Err(starlark::Error::new_other(anyhow::anyhow!(
        "stage() sandbox= must be a string (names a workflow sandbox_profiles entry) \
         or an inline sandbox_profile(..) value; got a {}",
        value.get_type()
    )))
}

/// Factory-as-loop foundation: decode + validate the `op=`/`label=` (and
/// `title=`/`body=`) kwargs against whether the stage routes to the
/// `workspace_effect` backend. A `forge_export` names no remote and no base:
/// the base is the run's frozen landable branch and the remote is inherited.
///
/// Returns `Some(WorkspaceEffect)` for a valid effect stage, `None` for an
/// ordinary stage. Rejects:
///   * a non-effect agent carrying any effect kwarg (`op`/`label`/forge fields),
///   * `agent="workspace_effect"` with a missing/invalid `op=`,
///   * forge fields (`title`/`body`) on any op other than `forge_export`.
pub(super) fn decode_workspace_effect(
    is_effect_agent: bool,
    op: &str,
    label: &str,
    title: &str,
    body: &str,
) -> starlark::Result<Option<kata_types::workflow::WorkspaceEffect>> {
    use kata_types::workflow::{ForgeExportSpec, WorkspaceEffect, WorkspaceEffectOp};

    // The forge-only kwargs, named for error messages.
    let forge_kwargs = [("title", title), ("body", body)];
    let any_forge_kwarg = || forge_kwargs.iter().find(|(_, value)| !value.is_empty());

    if !is_effect_agent {
        if !op.is_empty() {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "stage() op={op:?} is only valid on a workspace-effect stage \
                 (agent=\"workspace_effect\"); a non-effect stage must not carry op="
            )));
        }
        if !label.is_empty() {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "stage() label={label:?} is only valid on a workspace-effect stage \
                 (agent=\"workspace_effect\")"
            )));
        }
        if let Some((name, value)) = any_forge_kwarg() {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "stage() {name}={value:?} is only valid on a \
                 stage(agent=\"workspace_effect\", op=\"forge_export\")"
            )));
        }
        return Ok(None);
    }

    if op.is_empty() {
        return Err(starlark::Error::new_other(anyhow::anyhow!(
            "stage(agent=\"workspace_effect\") requires op=\"park\", op=\"promote\", \
             op=\"commit\", or op=\"forge_export\""
        )));
    }
    let op = WorkspaceEffectOp::from_label(op).ok_or_else(|| {
        starlark::Error::new_other(anyhow::anyhow!(
            "stage() op={op:?} is invalid; expected \"park\", \"promote\", \"commit\", or \
             \"forge_export\""
        ))
    })?;

    // Forge fields are only meaningful on forge_export; reject them elsewhere so
    // an author never silently mis-attaches a PR title to a park.
    let forge = if op == WorkspaceEffectOp::ForgeExport {
        Some(ForgeExportSpec {
            title: (!title.is_empty()).then(|| title.to_owned()),
            body: (!body.is_empty()).then(|| body.to_owned()),
        })
    } else {
        if let Some((name, value)) = any_forge_kwarg() {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "stage() {name}={value:?} is only valid on op=\"forge_export\"; op={:?} \
                 does not accept it",
                op.as_str()
            )));
        }
        None
    };

    Ok(Some(WorkspaceEffect {
        op,
        label: (!label.is_empty()).then(|| label.to_owned()),
        forge,
        // NEVER authorable. The candidate tree pin is a runtime fact resolved
        // from durable validation evidence by the runner at dispatch, not
        // something a pack may name — a pack that could name the tree it wants
        // to be measured against could name the tree it just wrote. There is
        // deliberately no keyword that reaches this field.
        candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
    }))
}

/// Render the literal directive prompt for a `workspace_effect` stage. Shared
/// with the backend via [`kata_types::workflow::WorkspaceEffect::directive_prompt`].
pub(super) fn workspace_effect_prompt(effect: &kata_types::workflow::WorkspaceEffect) -> String {
    effect.directive_prompt()
}

/// Decode the `workflow(sandbox_profiles={name:
/// sandbox_profile(..)})` dict into a name → profile-JSON
/// [`std::collections::BTreeMap`].
///
/// `WorkflowDefinition::sandbox_profiles` is a `BTreeMap<String, SandboxProfile>`
/// (key-sorted), so this collects into a `BTreeMap` to fix the key order — and
/// thereby the normalized-definition hash. Keys must be strings; each value must
/// be a `sandbox_profile(..)`. The carried JSON is lowered through the single
/// shared `sandbox_profile_from_json` decode for the native graph DSL.
pub(super) fn decode_sandbox_profiles(
    profiles: Option<DictRef<'_>>,
) -> starlark::Result<std::collections::BTreeMap<String, JsonValue>> {
    let mut out = std::collections::BTreeMap::new();
    let Some(profiles) = profiles else {
        return Ok(out);
    };
    for (key, value) in profiles.iter() {
        let name = key.unpack_str().ok_or_else(|| {
            starlark::Error::new_other(anyhow::anyhow!(
                "workflow() sandbox_profiles keys must be strings (profile names); got a {}",
                key.get_type()
            ))
        })?;
        // `host` is the RESERVED spelling of the unconfined
        // opt-out, lowered by `sandbox_ref_from_json` before any map lookup. A
        // profile registered under it could never be reached — and admitting
        // one would let a pack redefine the one word that means "unconfined".
        if name == kata_types::sandbox::HOST_SANDBOX_SPELLING {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "workflow() sandbox_profiles[\"{name}\"] is refused: `{name}` is the reserved \
                 spelling of the explicit unconfined opt-out (`stage(sandbox = \"host\")` runs \
                 the stage with full ambient host authority and says so) and may not name a \
                 profile. Register the profile under another name."
            )));
        }
        let Some(profile) = SandboxProfileValue::from_value(value) else {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "workflow() sandbox_profiles[{name:?}] must be a sandbox_profile(..) value; \
                 got a {}",
                value.get_type()
            )));
        };
        out.insert(name.to_owned(), profile.json.clone());
    }
    Ok(out)
}

// ── workflow-level orchestration-extension decoding ─────────────────────────

/// Insert an optional non-empty string field into a section/item JSON object.
///
/// Omitting the field (`None`, or an empty string for the `&str`-typed kwargs)
/// leaves the key absent so the shared serde `default` applies.
pub(super) fn insert_opt_str(obj: &mut serde_json::Map<String, JsonValue>, key: &str, value: &str) {
    if !value.is_empty() {
        obj.insert(key.to_owned(), JsonValue::String(value.to_owned()));
    }
}

/// Insert a `Vec<String>` array field only when non-empty so the shared serde
/// `default` applies on omission.
pub(super) fn insert_str_array(
    obj: &mut serde_json::Map<String, JsonValue>,
    key: &str,
    values: &[String],
) {
    if !values.is_empty() {
        obj.insert(
            key.to_owned(),
            JsonValue::Array(values.iter().cloned().map(JsonValue::String).collect()),
        );
    }
}

/// Insert a `Vec<String>` array field when the kwarg was PRESENT (even if
/// explicitly empty), and omit it only when the kwarg was OMITTED (`None`) so
/// the shared serde `default` applies. Unlike [`insert_str_array`], this
/// distinguishes an author's explicit empty list (`statuses=[]` → present-empty
/// → the shared `validate_extensions` rejects it) from omission (→ key absent → serde default). Used for the
/// fields whose serde default is NON-empty (e.g. `statuses` → `["active"]`),
/// where conflating empty with unset would change semantics.
pub(super) fn insert_str_array_opt(
    obj: &mut serde_json::Map<String, JsonValue>,
    key: &str,
    values: Option<&UnpackListOrTuple<String>>,
) {
    if let Some(values) = values {
        obj.insert(
            key.to_owned(),
            JsonValue::Array(
                values
                    .items
                    .iter()
                    .cloned()
                    .map(JsonValue::String)
                    .collect(),
            ),
        );
    }
}

/// Decode an optional positive count kwarg used by the extension constructors
/// (`max_objects=` / `max_items=` and the per-section `max_*=` caps).
///
/// `-1` (the unset sentinel) omits the key so the section normalizer applies its
/// own default. A value `>= 0` is taken verbatim; the shared `validate_extensions`
/// rejects an out-of-range `0`. A value
/// below `-1` is a clear authoring error.
pub(super) fn decode_opt_count(
    value: i64,
    owner: &str,
    field: &str,
) -> starlark::Result<Option<u32>> {
    match value {
        -1 => Ok(None),
        n if n >= 0 => u32::try_from(n).map(Some).map_err(|_| {
            starlark::Error::new_other(anyhow::anyhow!(
                "{owner} {field}= is out of range for a 32-bit count; got {n}"
            ))
        }),
        n => Err(starlark::Error::new_other(anyhow::anyhow!(
            "{owner} {field}= must be >= 0 (or omitted to use the default); got {n}"
        ))),
    }
}

/// Collect a `workflow()` extension list kwarg of typed item values into the
/// section's items array, returning `None` when the list is empty (so the kwarg
/// being unset leaves the whole section omitted).
///
/// `extract` pulls the carried per-item JSON out of each value, erroring with a
/// clear DSL message naming the expected constructor when an element is the
/// wrong type.
fn collect_extension_items<'v>(
    items: &[Value<'v>],
    extract: impl Fn(Value<'v>) -> Option<JsonValue>,
    expected: &str,
) -> starlark::Result<Option<Vec<JsonValue>>> {
    if items.is_empty() {
        return Ok(None);
    }
    let mut out = Vec::with_capacity(items.len());
    for value in items {
        let Some(json) = extract(*value) else {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "workflow() {expected} list entries must be {expected}(..) values; got a {}",
                value.get_type()
            )));
        };
        out.push(json);
    }
    Ok(Some(out))
}

/// Assemble the `external_input_channels` / `memory_selectors` /
/// `memory_writebacks` / `human_request_queue` section JSON from its collected
/// items plus an optional `max_*` cap in the normalized section
/// shape (`{<max_key>: .., <items_key>: [..]}`).
///
/// The section is emitted when EITHER it carries items OR an explicit `max_*`
/// cap was passed. Supplying only a cap — e.g.
/// `human_request_queue(max_items = 4)` with
/// no requests — lowers to a present section that reserves capacity
/// (`HumanRequestQueue { max_items: 4, requests: [] }`), distinct from an
/// omitted section (`max_items: 0`). With neither items nor a cap the section is
/// omitted.
fn capped_section(
    items: Option<Vec<JsonValue>>,
    max: Option<u32>,
    max_key: &str,
    items_key: &str,
) -> Option<JsonValue> {
    // Omit the section only when the author supplied neither items nor a cap.
    if items.is_none() && max.is_none() {
        return None;
    }
    let mut obj = serde_json::Map::new();
    if let Some(max) = max {
        obj.insert(max_key.to_owned(), JsonValue::from(max));
    }
    obj.insert(
        items_key.to_owned(),
        JsonValue::Array(items.unwrap_or_default()),
    );
    Some(JsonValue::Object(obj))
}

/// The collected, still-typed `workflow()` extension kwargs, passed to
/// [`decode_workflow_extensions`] to keep the `workflow()` builtin's argument
/// count manageable.
pub(super) struct WorkflowExtensionArgs<'a, 'v> {
    pub(super) memory_selectors: &'a [Value<'v>],
    pub(super) max_memory_selectors: i64,
    pub(super) memory_writebacks: &'a [Value<'v>],
    pub(super) max_memory_writebacks: i64,
    pub(super) validation_criteria: &'a [Value<'v>],
    pub(super) external_input_channels: &'a [Value<'v>],
    pub(super) max_external_input_channels: i64,
    pub(super) human_requests: &'a [Value<'v>],
    pub(super) max_human_requests: i64,
    pub(super) workflow_pattern: Option<Value<'v>>,
}

/// Assemble normalized extension-section JSON from the `workflow()`
/// extension kwargs into a [`WorkflowExtensionsJson`] the builder lowers through
/// the shared `normalize_extensions_from_json`.
///
/// Each list kwarg is collected into its section's items array (an unset/empty
/// list omits the whole section);
/// the optional `max_*` caps are folded in via [`capped_section`]. The single
/// `workflow_pattern=` value carries its own JSON. The assembled normalized
/// helper shape lowers to canonical `WorkflowExtensions`.
pub(super) fn decode_workflow_extensions(
    args: WorkflowExtensionArgs<'_, '_>,
) -> starlark::Result<WorkflowExtensionsJson> {
    let memory_selectors = collect_extension_items(
        args.memory_selectors,
        |v| MemorySelectorValue::from_value(v).map(|s| s.json.clone()),
        "memory_selector",
    )?;
    let memory_writebacks = collect_extension_items(
        args.memory_writebacks,
        |v| MemoryWritebackValue::from_value(v).map(|w| w.json.clone()),
        "memory_writeback",
    )?;
    let validation_criteria = collect_extension_items(
        args.validation_criteria,
        |v| ValidationCriterionValue::from_value(v).map(|c| c.json.clone()),
        "validation_criterion",
    )?;
    let external_input_channels = collect_extension_items(
        args.external_input_channels,
        |v| ChannelValue::from_value(v).map(|c| c.json.clone()),
        "channel",
    )?;
    let human_requests = collect_extension_items(
        args.human_requests,
        |v| HumanRequestValue::from_value(v).map(|r| r.json.clone()),
        "human_request",
    )?;

    let max_memory_selectors = decode_opt_count(
        args.max_memory_selectors,
        "workflow()",
        "max_memory_selectors",
    )?;
    let max_memory_writebacks = decode_opt_count(
        args.max_memory_writebacks,
        "workflow()",
        "max_memory_writebacks",
    )?;
    let max_external_input_channels = decode_opt_count(
        args.max_external_input_channels,
        "workflow()",
        "max_external_input_channels",
    )?;
    let max_human_requests =
        decode_opt_count(args.max_human_requests, "workflow()", "max_human_requests")?;

    let workflow_pattern = match args.workflow_pattern {
        Some(value) => {
            let Some(pattern) = WorkflowPatternValue::from_value(value) else {
                return Err(starlark::Error::new_other(anyhow::anyhow!(
                    "workflow() workflow_pattern= must be a workflow_pattern(..) value; got a {}",
                    value.get_type()
                )));
            };
            Some(pattern.json.clone())
        }
        None => None,
    };

    Ok(WorkflowExtensionsJson {
        human_request_queue: capped_section(
            human_requests,
            max_human_requests,
            "max_items",
            "requests",
        ),
        external_input_channels: capped_section(
            external_input_channels,
            max_external_input_channels,
            "max_channels",
            "channels",
        ),
        memory_selectors: capped_section(
            memory_selectors,
            max_memory_selectors,
            "max_selectors",
            "selectors",
        ),
        memory_writebacks: capped_section(
            memory_writebacks,
            max_memory_writebacks,
            "max_writebacks",
            "writebacks",
        ),
        // `validation_criteria` has no `max_*` cap in its normalized section shape.
        validation_criteria: validation_criteria.map(|criteria| {
            let mut obj = serde_json::Map::new();
            obj.insert("criteria".to_owned(), JsonValue::Array(criteria));
            JsonValue::Object(obj)
        }),
        workflow_pattern,
    })
}

/// Convert a Starlark value to JSON via `Value::to_json_value`, used by
/// `sandbox_profile(..)` for the string-or-dict `exec`/`fs`/`net` sub-fields and
/// the `secrets`/`image` sub-objects so the native graph DSL feeds JSON to
/// the single shared `sandbox_profile_from_json` decoder.
pub(super) fn value_to_json(value: Value<'_>, field: &str) -> starlark::Result<JsonValue> {
    value.to_json_value().map_err(|err| {
        starlark::Error::new_other(anyhow::anyhow!("sandbox_profile() {field}=: {err}"))
    })
}

/// Decode a single `gate=` argument of `loop()` into a stage id.
///
/// The gate is always a *single* stage reference — a `StageRef` (or stage-id
/// string). A list/tuple is a clear authoring error (the gate is one stage);
/// any other type is a clean type error.
pub(super) fn decode_single_stage(arg_name: &str, value: Value<'_>) -> starlark::Result<String> {
    if UnpackListOrTuple::<Value<'_>>::unpack_value(value)?.is_some() {
        return Err(starlark::Error::new_other(anyhow::anyhow!(
            "loop() {arg_name}= must be a single stage(..) reference, not a list"
        )));
    }
    decode_stage_ref(value)
}

/// Decode the `body=` argument of `loop()` into an ORDERED body sub-DAG member
/// list.
///
/// The body may be:
///
/// * a single `stage(..)` reference (or stage-id string) ⇒ a one-element body
///   `[stage]` — the single-stage loop;
/// * a `sequence(..)` handle ⇒ the sequence's full ordered members (recovered
///   from the builder via [`builder::resolve_body_members`]) — the natural
///   multi-stage body;
/// * an explicit list/tuple of stage references ⇒ those stages in order, the
///   ordered body sub-DAG (entry … exit). An empty list is rejected.
///
/// The LAST element is the body's EXIT stage (the loop's `worker_stage`, the
/// one the gate reads + depends on).
pub(super) fn decode_loop_body(value: Value<'_>) -> starlark::Result<Vec<String>> {
    if let Some(list) = UnpackListOrTuple::<Value<'_>>::unpack_value(value)? {
        if list.items.is_empty() {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "loop() body= list must name at least one stage"
            )));
        }
        return list
            .items
            .iter()
            .map(|item| decode_stage_ref(*item))
            .collect();
    }
    // A single handle: either a bare stage or a sequence() tail. Resolve the
    // sequence's ordered members (a bare stage resolves to itself).
    let id = decode_stage_ref(value)?;
    Ok(builder::resolve_body_members(&id))
}

/// Decode a `branch()` arm value into its target stage ids.
///
/// An arm value is a single `stage(..)` reference (or stage-id string) or a
/// list/tuple of them. An empty list is rejected here (an arm with no targets is
/// an authoring error); each element decodes through [`decode_stage_ref`].
pub(super) fn decode_branch_arm_targets(
    tag: &str,
    value: Value<'_>,
) -> starlark::Result<Vec<String>> {
    if let Some(list) = UnpackListOrTuple::<Value<'_>>::unpack_value(value)? {
        if list.items.is_empty() {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "branch() arm {tag:?} target list must not be empty"
            )));
        }
        return list
            .items
            .iter()
            .map(|item| decode_stage_ref(*item))
            .collect();
    }
    Ok(vec![decode_stage_ref(value)?])
}

/// Decode `stage(execution_requirements = {...})`.
///
/// # What this REFUSES, exactly
///
/// 1. A key outside `{containment, network, determinism, cacheable}`, with the
///    accepted menu in the message.
/// 2. A key naming one of the four DERIVED-MECHANICAL axes — `computation`,
///    `workspace`, `external_issuance`, `pre_commit_recovery` — refused BY NAME
///    rather than falling through to (1), because "unknown key" is the wrong
///    diagnosis for a real axis an author is deliberately not allowed to state.
///    `workspace` redirects to `cacheable`, which is its author-knowable form.
/// 3. A value that is not a spelling of the named key's domain.
/// 4. `network = "brokered_only"`. It is a real [`Network`] value that NOTHING
///    derives, so a declaration naming it could never agree with any derivation.
///    It falls out of (3) for free because [`DeclaredNetwork`] has no variant for
///    it — the refusal is the type's shape, not a special case.
/// 5. A non-string key, or a value of the wrong type for its key.
/// 6. `execution_requirements = {}` — an empty map states nothing, and "no claim"
///    is spelled by omitting the kwarg. Accepting both spellings for one meaning
///    is the `Omitted`/`Exempted` collapse `AuthoredCachePolicy` needs a
///    durable enum variant to keep apart.
///
/// # What it does NOT refuse
///
/// A declaration that DISAGREES with the derivation. That is not knowable here —
/// the derivation needs the resolved sandbox profiles and the whole stage — and
/// it is the compile door's job (`refuse_declared_class_mismatch`). This function
/// only decides whether the author wrote something well-formed.
pub(super) fn decode_execution_requirements(
    dict: &starlark::values::dict::DictRef<'_>,
) -> starlark::Result<kata_types::execution_class::StageClassDeclaration> {
    use kata_types::execution_class::{
        Containment, DECLARABLE_CONTAINMENT, DECLARABLE_DETERMINISM, DECLARABLE_NETWORK,
        DeclaredNetwork, Determinism, StageClassDeclaration,
    };

    /// The axes an author may NOT declare, each with why.
    const DERIVED_ONLY: &[(&str, &str)] = &[
        (
            "computation",
            "it is derived from the stage's op and executor, which the author already \
             chose by writing agent= and run=/prompt=",
        ),
        (
            "workspace",
            "it is derived from the declared filesystem policy and produces_files. If what \
             you mean is \"this stage must stay content-cache eligible\", declare \
             cacheable = True",
        ),
        (
            "external_issuance",
            "it is derived from whether the stage is a model call or reaches the network",
        ),
        (
            "pre_commit_recovery",
            "it is derived from the issuance axis and is the recovery LADDER, not a knob",
        ),
    ];

    let mut declared = StageClassDeclaration::default();
    let mut saw_any = false;

    for (key, value) in dict.iter() {
        let key = key.unpack_str().ok_or_else(|| {
            starlark::Error::new_other(anyhow::anyhow!(
                "stage() execution_requirements keys must be strings; got {key}"
            ))
        })?;
        saw_any = true;

        if let Some((_, why)) = DERIVED_ONLY.iter().find(|(name, _)| *name == key) {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "stage() execution_requirements cannot declare {key:?} — {why}. The declarable \
                 keys are \"containment\", \"network\", \"determinism\" and \"cacheable\""
            )));
        }

        let spelling = || {
            value.unpack_str().ok_or_else(|| {
                starlark::Error::new_other(anyhow::anyhow!(
                    "stage() execution_requirements {key:?} must be a string; got {value}"
                ))
            })
        };
        let refuse = |accepted: &[&str], got: &str| {
            starlark::Error::new_other(anyhow::anyhow!(
                "stage() execution_requirements {key:?}={got:?} is not one of {}",
                accepted
                    .iter()
                    .map(|tag| format!("{tag:?}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        };

        match key {
            "containment" => {
                let got = spelling()?;
                declared.containment = Some(
                    Containment::from_label(got)
                        .ok_or_else(|| refuse(DECLARABLE_CONTAINMENT, got))?,
                );
            }
            "network" => {
                let got = spelling()?;
                declared.network = Some(
                    DeclaredNetwork::from_label(got)
                        .ok_or_else(|| refuse(DECLARABLE_NETWORK, got))?,
                );
            }
            "determinism" => {
                let got = spelling()?;
                declared.determinism = Some(
                    Determinism::from_label(got)
                        .ok_or_else(|| refuse(DECLARABLE_DETERMINISM, got))?,
                );
            }
            "cacheable" => {
                declared.cacheable = Some(value.unpack_bool().ok_or_else(|| {
                    starlark::Error::new_other(anyhow::anyhow!(
                        "stage() execution_requirements \"cacheable\" must be True or False; \
                         got {value}"
                    ))
                })?);
            }
            other => {
                return Err(starlark::Error::new_other(anyhow::anyhow!(
                    "stage() execution_requirements has no key {other:?}. The declarable keys \
                     are \"containment\", \"network\", \"determinism\" and \"cacheable\""
                )));
            }
        }
    }

    if !saw_any {
        return Err(starlark::Error::new_other(anyhow::anyhow!(
            "stage() execution_requirements={{}} states nothing. Omit the kwarg entirely to \
             declare nothing — an empty map and an absent kwarg would be two spellings of one \
             meaning, and this surface keeps exactly one"
        )));
    }

    Ok(declared)
}

#[cfg(test)]
mod cache_policy_decode_tests {
    use kata_types::cache::CachePolicy;

    use super::decode_cache_policy;

    /// The AUTHORING surface, end to end through the real decoder.
    ///
    /// `""` decodes to `CachePolicy::Omitted` and does not alias the two
    /// exemption spellings: an author who says nothing and an author who says
    /// `no_cache` reach different durable values.
    ///
    /// **Would red if:** the `no_cache` exemption spelling were dropped, or the
    /// omitted kwarg started aliasing an exemption again (which is the state in
    /// which the default-on content cache is dead code on every shipped pack).
    #[test]
    fn the_kwarg_spellings_decode_to_the_durable_policy() {
        for (spelling, expected) in [
            ("", CachePolicy::Omitted),
            ("disabled", CachePolicy::Disabled),
            ("no_cache", CachePolicy::Disabled),
            ("model_reuse", CachePolicy::ModelReuse),
            ("content_cache", CachePolicy::ContentCache),
        ] {
            assert_eq!(
                decode_cache_policy(spelling).expect("accepted spelling"),
                expected,
                "cache_policy={spelling:?}"
            );
        }
    }

    /// `"omitted"` is RESERVED and cannot be authored — omission is spelled by
    /// omitting the kwarg. The refusal names that, rather than listing spellings
    /// and leaving the author to guess why a word that means what they meant is
    /// rejected.
    ///
    /// **Would red if:** the reserved tag became authorable, which is exactly
    /// how an author would claim the wire tag the (a) state now HAS
    /// (`CachePolicy::Omitted::as_tag`).
    #[test]
    fn the_reserved_spelling_is_refused_with_its_own_message() {
        let err = decode_cache_policy("omitted").expect_err("reserved");
        let msg = format!("{err}");
        assert!(
            msg.contains("RESERVED"),
            "the reserved refusal must say so; got: {msg}"
        );
        assert!(
            msg.contains("leaving cache_policy= off the stage"),
            "and it must name the way to spell omission; got: {msg}"
        );
    }

    /// An unknown spelling is refused echoing what the author wrote and listing
    /// every authorable one.
    #[test]
    fn an_unknown_spelling_lists_the_domain() {
        let msg = format!(
            "{}",
            decode_cache_policy("replay_safe").expect_err("an unknown spelling")
        );
        for expected in [
            "\"disabled\"",
            "\"no_cache\"",
            "\"model_reuse\"",
            "\"content_cache\"",
            "Omit the kwarg",
            "replay_safe",
        ] {
            assert!(
                msg.contains(expected),
                "the refusal must contain {expected:?}; got: {msg}"
            );
        }
    }
}
