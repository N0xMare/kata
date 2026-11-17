//! Native contract DSL — the `kata_contract_globals` builtin family.
//!
//! Pure relocation of the contract-constructor builtins (`contract` / `field` /
//! `enum` / `list_of` / `variant` / `number` / `integer` / `string`) out of the
//! former single `dsl` module.
// The `#[starlark_module]` expansion requires the builtins to spell `'v`
// explicitly, which trips `clippy::elidable_lifetime_names`.
#![allow(clippy::elidable_lifetime_names)]

use starlark::environment::GlobalsBuilder;
use starlark::starlark_module;
use starlark::values::Value;
use starlark::values::dict::DictRef;
use starlark::values::tuple::UnpackTuple;

use super::decode::{decode_numeric_constraints, decode_string_constraints, decode_type};
use super::schema::{self, ContractField, ContractShape, Primitive};
use super::values::{Contract, EnumType, Field, ListType, PrimitiveType, VariantType};

/// Register the native contract-DSL builtins on `builder`.
///
/// Wired into the evaluator via
/// `GlobalsBuilder::standard().with(kata_contract_globals).build()`.
#[starlark_module]
pub(crate) fn kata_contract_globals(builder: &mut GlobalsBuilder) {
    /// Construct a named object contract from an ordered `fields` dict of
    /// `field()` values.
    ///
    /// `contract("Plan", {"summary": field("string"), "steps": field(list_of("string"))})`
    ///
    /// Fields are read in the dict's insertion order (JSON object key order in
    /// the generated schema is not significant for validation). The generated
    /// schema is the constrained JSON-Schema object the agent-run validator
    /// accepts; any validator bound a contract would violate (nesting depth,
    /// field/variant count, name/tag shape, enum membership) is rejected here,
    /// at construction.
    fn contract<'v>(
        #[starlark(require = pos)] name: &str,
        #[starlark(require = pos)] fields: DictRef<'v>,
    ) -> starlark::Result<Contract> {
        let mut contract_fields = Vec::with_capacity(fields.len());
        for (key, value) in fields.iter() {
            let field_name = key.unpack_str().ok_or_else(|| {
                starlark::Error::new_other(anyhow::anyhow!(
                    "contract({name:?}) field names must be strings; got a {}",
                    key.get_type()
                ))
            })?;
            let Some(field) = Field::from_value(value) else {
                return Err(starlark::Error::new_other(anyhow::anyhow!(
                    "contract({name:?}) field {field_name:?} must be a field(..) \
                     value; got a {}",
                    value.get_type()
                )));
            };
            // `default=`/`secret=` are invocation-param kwargs, meaningless
            // on a structured-output contract field. Reject them here so a
            // mis-attached kwarg is a clear author-time error, not a silent drop.
            if field.default.is_some() || field.secret {
                return Err(starlark::Error::new_other(anyhow::anyhow!(
                    "contract({name:?}) field {field_name:?} sets default=/secret=, which are \
                     only valid on a workflow(params={{..}}) field, not a contract(..) field"
                )));
            }
            contract_fields.push(ContractField {
                name: field_name.to_owned(),
                ty: field.ty.clone(),
                // Unspelled `required=` means the documented default, `True`.
                required: field.required.unwrap_or(true),
                doc: field.doc.clone(),
            });
        }
        let shape = ContractShape {
            name: name.to_owned(),
            fields: contract_fields,
        };
        let json_schema = schema::contract_schema(&shape)
            .map_err(|err| starlark::Error::new_other(anyhow::anyhow!("{err}")))?;
        Ok(Contract {
            shape,
            schema: json_schema,
        })
    }

    /// Render an illustrative, pretty-printed JSON SKELETON string for a
    /// `contract(..)` value — the single-source prompt example.
    ///
    /// `json_skeleton(contract("Plan", {"summary": field("string"), "steps": field(list_of("string"))}))`
    /// returns the pretty JSON text
    /// ```json
    /// {
    ///   "summary": "<string>",
    ///   "steps": [
    ///     "<string>"
    ///   ]
    /// }
    /// ```
    /// Keys are emitted in DECLARATION order. The text is PURELY ILLUSTRATIVE
    /// (placeholders such as `"<string>"` are never fed to the closed
    /// structured-output validator), so it is safe to inline into a prompt.
    /// Pair it with `json_only(..)` to build the "respond with exactly one JSON
    /// object" preamble from the SAME `produces=contract(..)` schema, killing the
    /// hand-restated JSON block.
    fn json_skeleton<'v>(
        #[starlark(require = pos)] contract: Value<'v>,
    ) -> starlark::Result<String> {
        let Some(contract) = Contract::from_value(contract) else {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "json_skeleton(..) requires a contract(..) value; got a {}",
                contract.get_type()
            )));
        };
        Ok(schema::contract_skeleton(&contract.shape))
    }

    /// Declare a single contract field.
    ///
    /// `ty` may be a primitive spelling string (`"string"`, `"number"`,
    /// `"integer"`, `"bool"`, `"null"`), or a marker from `enum()`,
    /// `list_of()`, `variant()`, or a nested `contract()`.
    ///
    /// `required` defaults to `True`; set `required=False` to omit the field
    /// from the object's `required` list. `doc` becomes the JSON-Schema
    /// `description` on the field's node.
    ///
    /// In a `produces=` contract, a `null` on a `required=False` field is the
    /// field being ABSENT: it is removed from the parsed output before
    /// validation, on every stage that declares the contract (agent and shell
    /// alike), so `stages.<id>.parsed` never carries it. On a `required=True`
    /// field, `null` is a value like any other, checked against the field's
    /// type. A `workflow(params=)` field has no such reading: a supplied `null`
    /// is checked against the field's type whether or not it is required.
    ///
    /// # Invocation-param kwargs
    ///
    /// When a `field(..)` is used as a `workflow(params={name: field(..)})`
    /// value it may also carry:
    /// * `default=<value>` — the value used when the param is not supplied. A
    ///   defaulted param is optional; spelling `required=True` ALONGSIDE
    ///   `default=` is a contradiction rejected at author time. The default is
    ///   validated against the field's declared type when the param is decoded.
    /// * `secret=True` — the value is a secret: operator projections and the
    ///   execution record never carry it, a refusal never echoes it, and the
    ///   authoritative invocation blob keeps the real value. A secret param must
    ///   be supplied at every invocation and must not carry a `default=` (a
    ///   plaintext secret must never live in pack source); spelling
    ///   `required=False` alongside it is likewise a contradiction rejected at
    ///   author time.
    ///
    /// Both rejections turn on an EXPLICIT `required=`. `field(ty, default=..)`
    /// and `field(ty, secret=True)` — which carry `required` only by its `True`
    /// default — are the ordinary spellings and are accepted unchanged.
    ///
    /// Both kwargs are ONLY meaningful on a param field; a `contract(..)` field
    /// that sets either is rejected by `contract(..)`.
    fn field<'v>(
        #[starlark(require = pos)] ty: Value<'v>,
        // `Option<bool>`, not `bool` — see `Field::required`.
        // An unspelled `required=` must stay distinguishable from an explicit
        // `required=True`, or the two contradictions documented above are the
        // same value as the ordinary spelling and cannot be rejected at all.
        #[starlark(require = named)] required: Option<bool>,
        #[starlark(require = named, default = "")] doc: &str,
        #[starlark(require = named)] default: Option<Value<'v>>,
        #[starlark(require = named, default = false)] secret: bool,
    ) -> starlark::Result<Field> {
        let ty = decode_type(ty)?;
        let doc = if doc.is_empty() {
            None
        } else {
            Some(doc.to_owned())
        };
        let default = match default {
            Some(value) => Some(value.to_json_value().map_err(|err| {
                starlark::Error::new_other(anyhow::anyhow!(
                    "field() default= must be a JSON value: {err}"
                ))
            })?),
            None => None,
        };
        Ok(Field {
            ty,
            required,
            doc,
            default,
            secret,
        })
    }

    /// Declare a bare-string enumeration: `enum("draft", "review", "done")`.
    ///
    /// Lowers to `{"type":"string","enum":[..]}`. At least one variant is
    /// required.
    fn r#enum<'v>(#[starlark(args)] variants: UnpackTuple<&'v str>) -> starlark::Result<EnumType> {
        let variants: Vec<String> = variants.items.iter().map(|s| (*s).to_owned()).collect();
        if variants.is_empty() {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "enum() requires at least one string variant"
            )));
        }
        Ok(EnumType { variants })
    }

    /// Declare a homogeneous list: `list_of("string")` or `list_of(contract(..))`.
    ///
    /// Lowers to an `array` node with `maxItems` defaulted to the validator's
    /// ceiling of 128.
    fn list_of<'v>(#[starlark(require = pos)] element: Value<'v>) -> starlark::Result<ListType> {
        let element = decode_type(element)?;
        Ok(ListType { element })
    }

    /// Declare a discriminated union from a dict of `tag -> payload type`.
    ///
    /// `variant({"text": contract("Text", {..}), "noop": contract("Noop", {})})`
    ///
    /// Each arm tag maps to any field type; use a nested `contract` for a
    /// structured payload, or `contract("X", {})` for a payload-less arm.
    /// Lowers to `{"type":"variant","variants":{..}}`.
    fn variant<'v>(#[starlark(require = pos)] arms: DictRef<'v>) -> starlark::Result<VariantType> {
        if arms.is_empty() {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "variant() requires at least one arm"
            )));
        }
        let mut decoded = Vec::with_capacity(arms.len());
        for (key, value) in arms.iter() {
            let tag = key.unpack_str().ok_or_else(|| {
                starlark::Error::new_other(anyhow::anyhow!(
                    "variant() arm tags must be strings; got a {}",
                    key.get_type()
                ))
            })?;
            decoded.push((tag.to_owned(), decode_type(value)?));
        }
        Ok(VariantType { arms: decoded })
    }

    /// Declare a `number` (JSON floating-point) leaf with optional inclusive
    /// range bounds (VALUE CONSTRAINTS).
    ///
    /// `number(min = 0, max = 100)` lowers to
    /// `{"type":"number","minimum":0,"maximum":100}` and is ENFORCED against a
    /// stage's emitted value: a number outside `[min, max]` is rejected at
    /// structured-output validation. `min`/`max` accept an int or float; omit a
    /// bound to leave that side unbounded. When both are given, `min <= max` is
    /// checked at author time.
    fn number<'v>(
        #[starlark(require = named)] min: Option<Value<'v>>,
        #[starlark(require = named)] max: Option<Value<'v>>,
    ) -> starlark::Result<PrimitiveType> {
        Ok(PrimitiveType {
            primitive: Primitive::Number,
            constraints: decode_numeric_constraints(min, max, "number()")?,
        })
    }

    /// Declare an `integer` leaf with optional inclusive range bounds (VALUE
    /// CONSTRAINTS). Like [`number`], but the value must be a JSON integer.
    ///
    /// `integer(min = 1, max = 5)` lowers to
    /// `{"type":"integer","minimum":1,"maximum":5}`.
    fn integer<'v>(
        #[starlark(require = named)] min: Option<Value<'v>>,
        #[starlark(require = named)] max: Option<Value<'v>>,
    ) -> starlark::Result<PrimitiveType> {
        Ok(PrimitiveType {
            primitive: Primitive::Integer,
            constraints: decode_numeric_constraints(min, max, "integer()")?,
        })
    }

    /// Declare a `string` leaf with optional VALUE CONSTRAINTS: a regex
    /// `pattern` and `min_length`/`max_length` bounds.
    ///
    /// `string(pattern = "^[a-z]+$", min_length = 1, max_length = 32)` lowers to
    /// `{"type":"string","pattern":"^[a-z]+$","minLength":1,"maxLength":32}` and
    /// is ENFORCED against a stage's emitted value: a string that does not match
    /// the pattern, or whose length is out of bounds, is rejected at
    /// structured-output validation. The pattern uses the Rust `regex` crate
    /// syntax (JSON-Schema `pattern` semantics: an unanchored search, so anchor
    /// with `^`/`$` for a full match) and is checked for compilability at author
    /// time. Omit a bound (or pass `pattern = ""`) to leave that constraint
    /// unset.
    fn string<'v>(
        #[starlark(require = named, default = "")] pattern: &str,
        #[starlark(require = named, default = -1)] min_length: i64,
        #[starlark(require = named, default = -1)] max_length: i64,
    ) -> starlark::Result<PrimitiveType> {
        Ok(PrimitiveType {
            primitive: Primitive::String,
            constraints: decode_string_constraints(pattern, min_length, max_length, "string()")?,
        })
    }
}
