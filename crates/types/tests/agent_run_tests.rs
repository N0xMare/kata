//! Tests for `crates/types/src/agent_run.rs`.

use kata_types::agent_run::{
    AgentRunId, AgentRunOutput, AgentRunRequest, AgentRunResult, AgentRunStatus, ByoExecPolicy,
    ByoFsPolicy, ByoNetPolicy, ByoSandboxRequest, validate_agent_run_allowed_tools,
    validate_agent_run_output_content, validate_agent_run_output_schema,
    validate_param_value_against_schema,
};
use kata_types::cache::TokenUsage;
use ulid::Ulid;

// ── AgentRunStatus ──────────────────────────────────────────────────────────

#[test]
fn agent_run_status_serializes_snake_case() {
    assert_eq!(
        serde_json::to_string(&AgentRunStatus::Completed).unwrap(),
        "\"completed\""
    );
    assert_eq!(
        serde_json::to_string(&AgentRunStatus::Failed).unwrap(),
        "\"failed\""
    );
    assert_eq!(
        serde_json::to_string(&AgentRunStatus::TimedOut).unwrap(),
        "\"timed_out\""
    );
}

#[test]
fn agent_run_status_all_are_terminal() {
    assert!(AgentRunStatus::Completed.is_terminal());
    assert!(AgentRunStatus::Failed.is_terminal());
    assert!(AgentRunStatus::TimedOut.is_terminal());
}

// ── AgentRunRequest ─────────────────────────────────────────────────────────

#[test]
fn agent_run_request_roundtrips_minimal() {
    let raw = serde_json::json!({
        "prompt": "write a hello world in rust",
        "agent": "default",
    });
    let req: AgentRunRequest = serde_json::from_value(raw).unwrap();
    assert_eq!(req.prompt, "write a hello world in rust");
    assert_eq!(req.agent.as_str(), "default");
    assert!(req.model_hint.is_none());
    assert!(req.timeout_ms.is_none());
    assert!(req.output_schema.is_none());
    assert!(req.allowed_tools.is_empty());
    assert!(req.sandbox.is_none());
}

#[test]
fn agent_run_request_roundtrips_full() {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {
            "summary": {"type": "string", "maxLength": 200},
            "passed": {"type": "boolean"}
        },
        "required": ["summary", "passed"],
        "additionalProperties": false
    });
    let orig = AgentRunRequest {
        prompt: "refactor this module".to_string(),
        agent: "reviewer".into(),
        model_hint: Some("claude-sonnet-4-6".into()),
        timeout_ms: Some(900_000),
        output_schema: Some(schema.clone()),
        allowed_tools: vec!["read_file".to_string(), "write_file".to_string()],
        sandbox: Some(ByoSandboxRequest {
            exec: ByoExecPolicy::Oci,
            fs: ByoFsPolicy::WorkspaceRw,
            net: ByoNetPolicy::Offline,
        }),
    };
    let s = serde_json::to_string(&orig).unwrap();
    let back: AgentRunRequest = serde_json::from_str(&s).unwrap();
    assert_eq!(back.prompt, orig.prompt);
    assert_eq!(back.model_hint, orig.model_hint);
    assert_eq!(back.timeout_ms, Some(900_000));
    assert_eq!(back.output_schema, Some(schema));
    assert_eq!(back.allowed_tools, ["read_file", "write_file"]);
    assert_eq!(back.sandbox, orig.sandbox);
}

#[test]
fn agent_run_request_null_output_schema_decodes_as_none() {
    let raw = serde_json::json!({
        "prompt": "write a hello world in rust",
        "agent": "default",
        "output_schema": null,
    });
    let req: AgentRunRequest = serde_json::from_value(raw).unwrap();
    assert!(req.output_schema.is_none());
}

/// `sandbox: {}` decodes every field to the model-stage default — `oci`,
/// `workspace_ro`, `offline` — which is `ByoSandboxRequest::default()`.
#[test]
fn agent_run_request_sandbox_defaults_are_the_model_stage_default_when_explicit_empty() {
    let raw = serde_json::json!({
        "prompt": "say hi",
        "agent": "default",
        "sandbox": {}
    });
    let req: AgentRunRequest = serde_json::from_value(raw).unwrap();
    let sandbox = req.sandbox.expect("explicit empty sandbox should decode");
    assert_eq!(sandbox.exec, ByoExecPolicy::Oci);
    assert_eq!(sandbox.fs, ByoFsPolicy::WorkspaceRo);
    assert_eq!(sandbox.net, ByoNetPolicy::Offline);
    assert_eq!(sandbox, ByoSandboxRequest::default());
}

#[test]
fn agent_run_request_rejects_unsupported_sandbox_forms() {
    // Any backend outside the two exposed is an unknown variant, naming the
    // spelling and both that exist — `podman` and `bwrap` included, never
    // aliased onto `oci`.
    for exec in ["podman", "bwrap", "firecracker"] {
        let request = serde_json::json!({
            "prompt": "say hi",
            "agent": "default",
            "sandbox": {"exec": exec}
        });
        let err = serde_json::from_value::<AgentRunRequest>(request)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(&format!("unknown variant `{exec}`"))
                && err.contains("`host`")
                && err.contains("`oci`"),
            "err={err}"
        );
    }
    let oci: ByoSandboxRequest =
        serde_json::from_value(serde_json::json!({"exec": "oci"})).expect("`oci` decodes");
    assert_eq!(oci.exec, ByoExecPolicy::Oci);

    let unknown_sandbox_field = serde_json::json!({
        "prompt": "say hi",
        "agent": "default",
        "sandbox": {"image": {"reference": "kata/rust:latest"}}
    });
    let err = serde_json::from_value::<AgentRunRequest>(unknown_sandbox_field).unwrap_err();
    assert!(err.to_string().contains("unknown field"), "err={err}");
}

#[test]
fn agent_run_allowed_tools_validator_enforces_bounds() {
    validate_agent_run_allowed_tools(&["read_file".to_string(), "write_file".to_string()]).unwrap();

    let err = validate_agent_run_allowed_tools(&[String::new()]).unwrap_err();
    assert!(err.contains("allowed_tools[0]"), "err={err}");

    let err = validate_agent_run_allowed_tools(&["x".repeat(257)]).unwrap_err();
    assert!(err.contains("256"), "err={err}");

    let too_many = std::iter::repeat_n("read_file".to_string(), 65).collect::<Vec<_>>();
    let err = validate_agent_run_allowed_tools(&too_many).unwrap_err();
    assert!(err.contains("64"), "err={err}");
}

#[test]
fn agent_run_output_schema_validator_accepts_constrained_object_schema() {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {
            "summary": {"type": "string", "minLength": 1, "maxLength": 200},
            "score": {"type": "integer"},
            "tags": {
                "type": "array",
                "items": {"type": "string", "maxLength": 40},
                "maxItems": 4
            }
        },
        "required": ["summary", "score"],
        "additionalProperties": false
    });

    validate_agent_run_output_schema(&schema).unwrap();
    let parsed = validate_agent_run_output_content(
        r#"```json
{"summary":"ok","score":3,"tags":["a"]}
```"#,
        &schema,
    )
    .unwrap();
    assert_eq!(parsed["summary"], "ok");
}

#[test]
fn agent_run_output_schema_validator_rejects_unsupported_forms() {
    let unsafe_schema = serde_json::json!({
        "type": "object",
        "additionalProperties": true
    });
    let err = validate_agent_run_output_schema(&unsafe_schema).unwrap_err();
    assert!(err.contains("additionalProperties"), "err={err}");

    let array_without_bound = serde_json::json!({
        "type": "object",
        "properties": {
            "items": {"type": "array", "items": {"type": "string"}}
        }
    });
    let err = validate_agent_run_output_schema(&array_without_bound).unwrap_err();
    assert!(err.contains("maxItems"), "err={err}");
}

#[test]
fn agent_run_output_schema_validator_rejects_required_without_properties() {
    let schema = serde_json::json!({
        "type": "object",
        "required": ["passed"]
    });

    let err = validate_agent_run_output_schema(&schema).unwrap_err();
    assert!(err.contains("required"), "err={err}");
    assert!(err.contains("undeclared property"), "err={err}");
}

#[test]
fn agent_run_output_schema_validator_rejects_unbounded_min_length() {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {
            "summary": {"type": "string", "minLength": 65_537}
        }
    });

    let err = validate_agent_run_output_schema(&schema).unwrap_err();
    assert!(err.contains("minLength"), "err={err}");
    assert!(err.contains("65536"), "err={err}");
}

#[test]
fn agent_run_output_content_validator_rejects_shape_mismatch() {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {
            "passed": {"type": "boolean"}
        },
        "required": ["passed"]
    });
    let err = validate_agent_run_output_content(r#"{"passed":"yes"}"#, &schema).unwrap_err();
    assert!(err.contains("passed"), "err={err}");
    assert!(err.contains("boolean"), "err={err}");
}

// ── AgentRunResult ──────────────────────────────────────────────────────────

#[test]
fn agent_run_result_completed_roundtrip() {
    let id = Ulid::from_string("01HV0VZTBP7TX5DQ1V0G7WB3SK").unwrap();
    let result = AgentRunResult {
        run_id: AgentRunId(id),
        status: AgentRunStatus::Completed,
        agent: "default".into(),
        result: Some(AgentRunOutput {
            content: "fn main() {}".to_string(),
            parsed: Some(serde_json::json!({"kind": "rust"})),
            token_usage: TokenUsage {
                input: 100,
                output: 20,
                cache_read: 0,
                cache_write: 0,
            },
            cost_micro_usd: 5_000,
            stop_reason: Some("end_turn".into()),
        }),
        error: None,
    };

    let s = serde_json::to_string(&result).unwrap();
    let back: AgentRunResult = serde_json::from_str(&s).unwrap();

    assert_eq!(back.status, AgentRunStatus::Completed);
    assert_eq!(back.run_id.0, id);
    let out = back.result.unwrap();
    assert_eq!(out.content, "fn main() {}");
    assert_eq!(out.parsed, Some(serde_json::json!({"kind": "rust"})));
    assert_eq!(out.cost_micro_usd, 5_000);
    assert_eq!(out.stop_reason.as_deref(), Some("end_turn"));
    assert!(back.error.is_none());
}

#[test]
fn agent_run_result_failed_roundtrip() {
    let id = Ulid::new();
    let result = AgentRunResult {
        run_id: AgentRunId(id),
        status: AgentRunStatus::Failed,
        agent: "default".into(),
        result: None,
        error: Some("agent process exited with code 1".to_string()),
    };

    let s = serde_json::to_string(&result).unwrap();
    let back: AgentRunResult = serde_json::from_str(&s).unwrap();

    assert_eq!(back.status, AgentRunStatus::Failed);
    assert!(back.result.is_none());
    assert_eq!(
        back.error.as_deref(),
        Some("agent process exited with code 1")
    );
}

#[test]
fn agent_run_result_timed_out_roundtrip() {
    let id = Ulid::new();
    let result = AgentRunResult {
        run_id: AgentRunId(id),
        status: AgentRunStatus::TimedOut,
        agent: "reviewer".into(),
        result: None,
        error: Some("exceeded timeout_ms=900000".to_string()),
    };

    let s = serde_json::to_string(&result).unwrap();
    let back: AgentRunResult = serde_json::from_str(&s).unwrap();
    assert_eq!(back.status, AgentRunStatus::TimedOut);
}

#[test]
fn agent_run_id_serializes_as_ulid_string() {
    let id = Ulid::from_string("01HV0VZTBP7TX5DQ1V0G7WB3SK").unwrap();
    let run_id = AgentRunId(id);
    let s = serde_json::to_string(&run_id).unwrap();
    // Ulid serde serializes as the base32 string.
    assert_eq!(s, "\"01HV0VZTBP7TX5DQ1V0G7WB3SK\"");
}

#[test]
fn agent_run_output_defaults_on_missing_optional_fields() {
    let raw = serde_json::json!({
        "content": "hello",
    });
    let out: AgentRunOutput = serde_json::from_value(raw).unwrap();
    assert_eq!(out.content, "hello");
    assert!(out.parsed.is_none());
    assert_eq!(out.cost_micro_usd, 0);
    assert!(out.stop_reason.is_none());
    assert_eq!(out.token_usage.input, 0);
}

// ── Contract enums + variants (typed-contract output validator) ─────────────

#[test]
fn output_schema_accepts_string_enum_and_validates_membership() {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {
            "risk": {"type": "string", "enum": ["low", "normal", "high"]}
        },
        "required": ["risk"],
        "additionalProperties": false
    });
    validate_agent_run_output_schema(&schema).unwrap();

    let ok = validate_agent_run_output_content(r#"{"risk":"normal"}"#, &schema).unwrap();
    assert_eq!(ok["risk"], "normal");

    let err = validate_agent_run_output_content(r#"{"risk":"medium"}"#, &schema).unwrap_err();
    assert!(err.contains("not one of"), "err={err}");
    assert!(err.contains("medium"), "err={err}");
}

#[test]
fn output_schema_rejects_malformed_and_misplaced_enum() {
    let empty = serde_json::json!({
        "type": "object",
        "properties": {"x": {"type": "string", "enum": []}}
    });
    let err = validate_agent_run_output_schema(&empty).unwrap_err();
    assert!(err.contains("at least one variant"), "err={err}");

    let dup = serde_json::json!({
        "type": "object",
        "properties": {"x": {"type": "string", "enum": ["a", "a"]}}
    });
    let err = validate_agent_run_output_schema(&dup).unwrap_err();
    assert!(err.contains("duplicate variant"), "err={err}");

    // enum is only valid on a string node
    let on_number = serde_json::json!({
        "type": "object",
        "properties": {"x": {"type": "integer", "enum": [1, 2]}}
    });
    let err = validate_agent_run_output_schema(&on_number).unwrap_err();
    assert!(err.contains("enum"), "err={err}");
}

#[test]
fn output_schema_accepts_variant_and_validates_discriminated_union() {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {
            "outcome": {
                "type": "variant",
                "variants": {
                    "approve": {"type": "object", "properties": {}, "additionalProperties": false},
                    "block": {
                        "type": "object",
                        "properties": {"reason": {"type": "string"}},
                        "required": ["reason"],
                        "additionalProperties": false
                    }
                }
            }
        },
        "required": ["outcome"],
        "additionalProperties": false
    });
    validate_agent_run_output_schema(&schema).unwrap();

    let ok = validate_agent_run_output_content(
        r#"{"outcome":{"block":{"reason":"tests fail"}}}"#,
        &schema,
    )
    .unwrap();
    assert_eq!(ok["outcome"]["block"]["reason"], "tests fail");

    // payload-less arm
    validate_agent_run_output_content(r#"{"outcome":{"approve":{}}}"#, &schema).unwrap();

    // unknown tag
    let err =
        validate_agent_run_output_content(r#"{"outcome":{"escalate":{}}}"#, &schema).unwrap_err();
    assert!(err.contains("variant tag"), "err={err}");
    assert!(err.contains("escalate"), "err={err}");

    // wrong payload (block missing required reason)
    let err =
        validate_agent_run_output_content(r#"{"outcome":{"block":{}}}"#, &schema).unwrap_err();
    assert!(err.contains("reason"), "err={err}");

    // multi-key variant object
    let err = validate_agent_run_output_content(
        r#"{"outcome":{"approve":{},"block":{"reason":"x"}}}"#,
        &schema,
    )
    .unwrap_err();
    assert!(err.contains("single-key"), "err={err}");
}

#[test]
fn output_schema_rejects_empty_variant_arms() {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {"o": {"type": "variant", "variants": {}}}
    });
    let err = validate_agent_run_output_schema(&schema).unwrap_err();
    assert!(err.contains("at least one arm"), "err={err}");
}

// ── VALUE CONSTRAINTS: minimum/maximum/pattern enforcement ───────────────────

#[test]
fn output_schema_accepts_numeric_range_and_enforces_it() {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {"score": {"type": "number", "minimum": 0, "maximum": 100}},
        "required": ["score"],
        "additionalProperties": false
    });
    validate_agent_run_output_schema(&schema).unwrap();

    // In-range passes.
    validate_agent_run_output_content(r#"{"score": 50}"#, &schema).unwrap();
    // Above maximum is rejected, naming the constraint.
    let err = validate_agent_run_output_content(r#"{"score": 150}"#, &schema).unwrap_err();
    assert!(err.contains("maximum"), "err={err}");
    // Below minimum is rejected.
    let err = validate_agent_run_output_content(r#"{"score": -5}"#, &schema).unwrap_err();
    assert!(err.contains("minimum"), "err={err}");
}

#[test]
fn output_schema_accepts_string_pattern_and_enforces_it() {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {"slug": {"type": "string", "pattern": "^[a-z]+$"}},
        "required": ["slug"],
        "additionalProperties": false
    });
    validate_agent_run_output_schema(&schema).unwrap();

    validate_agent_run_output_content(r#"{"slug": "abc"}"#, &schema).unwrap();
    let err = validate_agent_run_output_content(r#"{"slug": "ABC"}"#, &schema).unwrap_err();
    assert!(err.contains("pattern"), "err={err}");
}

#[test]
fn output_schema_rejects_uncompilable_pattern() {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {"s": {"type": "string", "pattern": "(unclosed"}}
    });
    let err = validate_agent_run_output_schema(&schema).unwrap_err();
    assert!(err.contains("not a valid regular expression"), "err={err}");
}

#[test]
fn output_schema_rejects_minimum_greater_than_maximum() {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {"n": {"type": "integer", "minimum": 10, "maximum": 1}}
    });
    let err = validate_agent_run_output_schema(&schema).unwrap_err();
    assert!(err.contains("minimum must be <= maximum"), "err={err}");
}

#[test]
fn output_schema_rejects_numeric_bound_on_string() {
    // A numeric bound key is only valid on a number/integer node.
    let schema = serde_json::json!({
        "type": "object",
        "properties": {"s": {"type": "string", "minimum": 0}}
    });
    let err = validate_agent_run_output_schema(&schema).unwrap_err();
    assert!(err.contains("minimum"), "err={err}");

    // …and a `pattern` is only valid on a string node.
    let on_number = serde_json::json!({
        "type": "object",
        "properties": {"n": {"type": "number", "pattern": "^x$"}}
    });
    let err = validate_agent_run_output_schema(&on_number).unwrap_err();
    assert!(err.contains("pattern"), "err={err}");
}

#[test]
fn integer_range_enforced_and_constraint_free_number_still_unbounded() {
    let bounded = serde_json::json!({
        "type": "object",
        "properties": {"n": {"type": "integer", "minimum": 1, "maximum": 5}},
        "required": ["n"],
        "additionalProperties": false
    });
    validate_agent_run_output_content(r#"{"n": 3}"#, &bounded).unwrap();
    let err = validate_agent_run_output_content(r#"{"n": 9}"#, &bounded).unwrap_err();
    assert!(err.contains("maximum"), "err={err}");

    // ADDITIVITY: an unconstrained number accepts the same out-of-range value,
    // proving the rejection above is caused by the constraint.
    let unbounded = serde_json::json!({
        "type": "object",
        "properties": {"n": {"type": "integer"}},
        "required": ["n"],
        "additionalProperties": false
    });
    validate_agent_run_output_content(r#"{"n": 9}"#, &unbounded).unwrap();
}

/// A `null` on an OPTIONAL property is the property being absent — at the top
/// level, inside an array item and inside a variant arm — and it is REMOVED
/// from the parsed document, so the parsed value equals the one an answer that
/// omitted the property would give. This is the strict structured-output
/// spelling of "optional" (`kata_types::strict_output_schema` sends optional
/// properties required-and-nullable).
#[test]
fn output_content_null_on_an_optional_property_is_absent() {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {
            "summary": {"type": "string"},
            "note": {"type": "string"},
            "items": {"type": "array", "maxItems": 4, "items": {
                "type": "object",
                "properties": {"path": {"type": "string"}, "line": {"type": "integer"}},
                "required": ["path"],
            }},
            "pick": {"type": "variant", "variants": {"one": {
                "type": "object",
                "properties": {"why": {"type": "string"}, "extra": {"type": "boolean"}},
                "required": ["why"],
            }}},
        },
        "required": ["summary", "items", "pick"],
        "additionalProperties": false,
    });
    let nulls = r#"{"summary":"s","note":null,"items":[{"path":"a","line":null}],
        "pick":{"one":{"why":"w","extra":null}}}"#;
    let omitted = r#"{"summary":"s","items":[{"path":"a"}],"pick":{"one":{"why":"w"}}}"#;
    let parsed = validate_agent_run_output_content(nulls, &schema)
        .expect("a null on an optional property is accepted as absent");
    assert_eq!(
        parsed,
        serde_json::from_str::<serde_json::Value>(omitted).unwrap(),
        "every optional null is removed, at every depth"
    );
    assert_eq!(
        validate_agent_run_output_content(omitted, &schema).unwrap(),
        parsed,
        "omission and null parse to the same document"
    );
}

/// A `null` on a REQUIRED property is still a value: it is checked against the
/// property's type and refused when the type is not `null`.
#[test]
fn output_content_null_on_a_required_property_is_still_refused() {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {"summary": {"type": "string"}, "gone": {"type": "null"}},
        "required": ["summary", "gone"],
    });
    let error = validate_agent_run_output_content(r#"{"summary":null,"gone":null}"#, &schema)
        .expect_err("a required string may not be null");
    assert!(
        error.contains("$.summary expected string but got null"),
        "{error}"
    );
    assert!(
        validate_agent_run_output_content(r#"{"summary":"s","gone":null}"#, &schema).is_ok(),
        "a required null-typed property takes null"
    );
}

/// Workflow params are NOT read the `produces=` way: a `null` on an optional
/// property of an object param, and a `null` param itself, are checked against
/// their type and refused.
#[test]
fn param_null_on_an_optional_property_is_still_a_value() {
    let object = serde_json::json!({
        "type": "object",
        "properties": {"a": {"type": "string"}, "b": {"type": "string"}},
        "required": ["a"],
        "additionalProperties": false,
    });
    validate_param_value_against_schema(&serde_json::json!({"a": "x"}), &object)
        .expect("an omitted optional property is accepted");
    let error =
        validate_param_value_against_schema(&serde_json::json!({"a": "x", "b": null}), &object)
            .expect_err("a null on an optional param property is a value");
    assert!(
        error.contains("$.b expected string but got null"),
        "{error}"
    );
    validate_param_value_against_schema(
        &serde_json::Value::Null,
        &serde_json::json!({"type": "string"}),
    )
    .expect_err("a null param is checked against its type");
}
