//! Load-time structured-output reference resolution.
//!
//! The `{{ stages.<producer>.parsed[.<path>] }}` template-reference checker
//! plus the conservative tolerant extractor it runs over
//! each stage's prompt template.

use kata_types::workflow::StageId;
use kata_types::{KataError, KataResult};
use smol_str::SmolStr;

use super::{
    ExecutionProgram, ExecutionProgramStage, ExecutionPromptRendering, VerifierDiagnostic,
    VerifierSeverity,
};

/// Load-time WHOLE-ENVELOPE + NESTED check for `{{ stages.<id>.parsed[.<path>] }}`
/// template references against the producer stage's declared output contract —
/// the rich `produces=contract(..)` schema when present, else the flat `outputs`
/// table.
///
/// Returns the collected `untyped_referenced_output` diagnostics — a downstream
/// `parsed` reference to a producer that declares NEITHER a `produces=` schema
/// NOR a flat `outputs` entry. These carry `VerifierSeverity::Error`: the
/// caller ([`super::compile`]) folds them into the verifier report and escalates
/// its status to `Error`, so a referenced-but-untyped edge is a hard load/check
/// FAILURE, not an advisory. A hard [`KataError::Validation`] is still returned
/// inline ONLY for a genuine DANGLING reference (unknown producer, or a path
/// segment the producer's schema/outputs cannot admit), a cross-stage TYPE
/// mismatch, or a producer outside the consumer's dependency closure
/// ([`check_dependency_closure_references`], which states that refused set).
///
/// SOUNDNESS — the hard-error path must NEVER false-positive on a valid pack. The
/// conservative guards that make that hold:
///
/// 1. Only `Template`-rendered prompts are scanned. A `Literal` prompt is
///    forwarded to the worker byte-for-byte (no minijinja pass), so a
///    `stages.x.parsed.y`-looking substring inside it is NOT a template
///    reference and must not be flagged. For the same reason `{% raw %} …
///    {% endraw %}` regions are skipped: minijinja emits their body verbatim
///    without rendering it, so a reference spelled inside one is literal text.
/// 2. The declared field set is resolved per the runtime's own precedence: a
///    rich `output_schema` (lowered from `produces=contract(..)`) is
///    AUTHORITATIVE — its contract object is CLOSED (the content validator
///    rejects undeclared keys), so each path segment is descended against the
///    schema's `properties`. Only when there is no rich schema is the flat
///    `outputs` set consulted (first segment only — the coarse table cannot
///    describe nesting).
/// 3. A WHOLE-ENVELOPE reference (`{{ stages.x.parsed }}`, empty path) is checked
///    for producer EXISTENCE only — a controller legitimately consuming an entire
///    upstream envelope must pass.
/// 4. Nested descent STOPS conservatively at any non-object node (array / variant
///    / leaf): a reference like `parsed.items.0` indexes INTO a value, which is
///    out of scope for the schema walk (never a false-reject).
pub(super) fn check_output_references(
    program: &ExecutionProgram,
) -> KataResult<Vec<VerifierDiagnostic>> {
    let mut untyped = Vec::new();
    for (consumer_id, stage) in &program.stages {
        // Guard 1: a literal-rendered prompt is not a minijinja template.
        if stage.op.prompt_rendering == ExecutionPromptRendering::Literal {
            continue;
        }
        check_dependency_closure_references(consumer_id, &stage.op.prompt_template, program)?;
        for reference in extract_parsed_output_references(&stage.op.prompt_template) {
            let OutputReference { producer, path } = &reference;
            let rendered = reference.render();
            let Some(producer_stage) = program.stages.get(&StageId(SmolStr::new(producer))) else {
                // Whole-envelope OR nested: an unknown producer is always a hard
                // dangling reference.
                return Err(KataError::Validation(format!(
                    "stage \"{}\" prompt references {{{{ {rendered} }}}} \
                     but \"{producer}\" is not a stage in this workflow (unknown producer stage)",
                    consumer_id.0
                )));
            };
            // When a producer carries a rich `output_schema` (lowered from
            // `produces=contract(..)`), that schema is AUTHORITATIVE at runtime —
            // dispatch validates against it and SKIPS the flat `outputs` check
            // (`runner::dispatch`). The contract object is CLOSED, so the runtime
            // `parsed` envelope holds EXACTLY the schema's declared property
            // names; a reference to a non-property field is genuinely dangling.
            if let Some(schema) = &producer_stage.policies.output_schema {
                check_reference_against_schema(consumer_id, stage, &reference, schema, &rendered)?;
                continue;
            }
            // No rich schema: consult the flat `outputs` table (coarse, first
            // segment only).
            if !producer_stage.outputs.is_empty() {
                // A whole-envelope reference is existence-only (the producer is
                // structured enough — a flat table exists).
                let Some(first) = path.first() else {
                    continue;
                };
                if !producer_stage
                    .outputs
                    .iter()
                    .any(|out| out.name.as_str() == first)
                {
                    let declared = producer_stage
                        .outputs
                        .iter()
                        .map(|out| out.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ");
                    return Err(KataError::Validation(format!(
                        "stage \"{}\" prompt references {{{{ {rendered} }}}} \
                         but producer stage \"{producer}\" declares no output named \"{first}\" \
                         (declared outputs: {declared}) — fix the field name or declare the output \
                         (dangling structured-output reference, load-time check)",
                        consumer_id.0
                    )));
                }
                continue;
            }
            // The producer declares NEITHER a `produces=`
            // schema NOR a flat `outputs` entry, yet a downstream stage references
            // its `parsed` envelope. This is a referenced-but-UNTYPED edge — a
            // hard `Error`.
            // Deliberately scoped to REFERENCED producers so it never flags a
            // legitimate unreferenced shell/effect/controller stage.
            let field_note = match path.first() {
                Some(first) => format!("field \"{first}\""),
                None => "its whole `parsed` envelope".to_owned(),
            };
            untyped.push(VerifierDiagnostic {
                severity: VerifierSeverity::Error,
                code: SmolStr::new("untyped_referenced_output"),
                stage: Some(producer_stage.stage_id.clone()),
                message: format!(
                    "stage \"{}\" references {{{{ {rendered} }}}} ({field_note}) but producer \
                     stage \"{producer}\" declares neither a produces=contract(..) schema nor a \
                     flat outputs= table, so the reference cannot be type-checked; declare \
                     produces= on \"{producer}\" to type the edge",
                    consumer_id.0
                ),
                span: None,
            });
        }
        // The other two STATICALLY-KNOWN prompt namespaces — the declared
        // `external_inputs.*` side-channels and the review-loop `review.*`
        // context. A typo in either boots the workflow and crashes at the
        // consumer's FIRST render (strict-undefined) AFTER upstream stages burned
        // budget; promote both to load time.
        check_external_input_references(consumer_id, &stage.op.prompt_template, program)?;
        check_review_references(consumer_id, &stage.op.prompt_template)?;
    }
    Ok(untyped)
}

/// Load-time check that every `{{ stages.<producer>… }}` read names a stage the
/// consumer transitively depends on.
///
/// Refuses `output_reference_outside_dependency_closure`, exactly: a reference
/// extracted from an expression block (`{{ … }}`: the producer itself or any
/// path under it, dotted or bracket-literal) whose producer is a stage of the program but not in
/// [`ExecutionProgram::dependency_closure`] of the consumer — a sibling branch, a
/// downstream stage, or the consumer itself. Such a producer is not ordered
/// before the consumer, so its envelope would be present or absent by scheduling
/// order. A producer that names no stage is left to the dangling-reference
/// checks; a whole-namespace `{{ stages }}` names no producer.
///
/// The runtime render context holds only the closure
/// ([`ExecutionProgram::outputs_in_dependency_closure`]), so a read this
/// extractor does not see (a statement block, a computed index) cannot reach
/// outside it either: it finds the producer absent on every schedule, never on
/// some.
fn check_dependency_closure_references(
    consumer_id: &StageId,
    template: &str,
    program: &ExecutionProgram,
) -> KataResult<()> {
    let references = extract_head_references(template, "stages");
    if references.is_empty() {
        return Ok(());
    }
    let closure = program.dependency_closure(consumer_id);
    for path in &references {
        let Some(producer) = path.first() else {
            continue;
        };
        let producer_id = StageId(SmolStr::new(producer));
        if !program.stages.contains_key(&producer_id) || closure.contains(&producer_id) {
            continue;
        }
        let rendered = render_head_reference("stages", path);
        return Err(KataError::Validation(format!(
            "output_reference_outside_dependency_closure: stage \"{consumer}\" prompt references \
             {{{{ {rendered} }}}} but \"{consumer}\" does not depend on \"{producer}\", \
             directly or through other stages, so no edge orders \"{producer}\" before it — \
             add \"{producer}\" to \"{consumer}\"'s depends_on (load-time check)",
            consumer = consumer_id.0
        )));
    }
    Ok(())
}

/// Load-time check for `{{ external_inputs.<name>[...] }}` references
/// against the program's DECLARED side-channels.
///
/// The runtime exposes `external_inputs` only when at least one channel is
/// declared, as a map keyed by each channel's `expose_as` alias plus the two
/// reserved views `by_channel` (keyed by channel id) and `channels` (keyed by
/// alias). Render is strict-undefined, so a reference to an UNDECLARED alias — or
/// ANY `external_inputs.*` reference in a program that declares no channels at
/// all — resolves to nothing and blows up at first render. Promote that to a hard
/// load-time error.
///
/// SOUNDNESS — the hard-error path must never false-positive on a valid pack:
/// * Only the FIRST segment is validated against the declared alias set; nested
///   access into a channel's value (`.items` / `.default_value` / …) descends
///   into a free-form runtime object and is left alone.
/// * A whole-namespace reference (`{{ external_inputs }}`) is existence-only —
///   valid as long as the program declares at least one channel.
/// * Channel VISIBILITY is per-stage at runtime (a `stage=`-scoped channel is
///   exposed only to its stage), but this check is deliberately PROGRAM-WIDE:
///   validating against the whole declared set catches the typo class (an alias
///   that exists NOWHERE) without risking a false-positive on the subtler
///   scoping cases the synthetic loop-iteration stage names complicate.
fn check_external_input_references(
    consumer_id: &StageId,
    template: &str,
    program: &ExecutionProgram,
) -> KataResult<()> {
    let refs = extract_head_references(template, "external_inputs");
    if refs.is_empty() {
        return Ok(());
    }
    let declared: std::collections::BTreeSet<&str> = program
        .external_input_channels
        .channels
        .iter()
        .map(|channel| channel.expose_as.as_str())
        .collect();
    for path in &refs {
        let rendered = render_head_reference("external_inputs", path);
        // A program that declares NO channels never defines the `external_inputs`
        // namespace, so any reference into it is dangling.
        if declared.is_empty() {
            return Err(KataError::Validation(format!(
                "stage \"{}\" prompt references {{{{ {rendered} }}}} but this workflow declares \
                 no external_input_channels, so the `external_inputs` namespace is never defined \
                 — declare the channel or remove the reference (dangling external-input reference, \
                 load-time check)",
                consumer_id.0
            )));
        }
        let Some(first) = path.first() else {
            // Whole-namespace reference: existence-only (channels exist).
            continue;
        };
        // The two reserved runtime views are always present alongside the aliases.
        if first == "by_channel" || first == "channels" {
            continue;
        }
        if !declared.contains(first.as_str()) {
            let mut names = declared.iter().copied().collect::<Vec<_>>();
            names.sort_unstable();
            return Err(KataError::Validation(format!(
                "stage \"{}\" prompt references {{{{ {rendered} }}}} but no external_input_channel \
                 exposes \"{first}\" (declared channel aliases: {}) — fix the alias or declare the \
                 channel (dangling external-input reference, load-time check)",
                consumer_id.0,
                names.join(", ")
            )));
        }
    }
    Ok(())
}

/// The fixed set of fields the review-loop runtime injects under the `review.*`
/// namespace (see `loops::render_review_context` /
/// `template::render_prompt_with_review`). A reference to any other first segment
/// is a genuine typo — the namespace carries at most these fields. `rollover` is
/// injected only from rollover generation 1 on, so a prompt that reads it guards it
/// with `is defined`; this check does not.
const REVIEW_CONTEXT_FIELDS: &[&str] = &["iteration", "previous_output", "feedback", "rollover"];

/// Load-time check for `{{ review.<field>[...] }}` references against the
/// review-loop context's fixed field set.
///
/// SOUNDNESS: only the FIRST segment is validated (nested access into
/// `previous_output` descends into a free-form worker envelope and is left
/// alone), and a whole-namespace `{{ review }}` reference is existence-only. The
/// check does NOT require the referencing stage to actually be a review-loop
/// stage: a `review.*` reference outside a loop is undefined at runtime too, but
/// flagging that needs loop-membership inference that risks false-positives, so
/// this stays a pure field-name check — the typo class this check targets.
fn check_review_references(consumer_id: &StageId, template: &str) -> KataResult<()> {
    for path in extract_head_references(template, "review") {
        let Some(first) = path.first() else {
            // Whole-namespace reference: existence-only.
            continue;
        };
        if !REVIEW_CONTEXT_FIELDS.contains(&first.as_str()) {
            let rendered = render_head_reference("review", &path);
            return Err(KataError::Validation(format!(
                "stage \"{}\" prompt references {{{{ {rendered} }}}} but the review-loop context \
                 exposes no field \"{first}\" (available fields: {}) — fix the field name \
                 (dangling review-context reference, load-time check)",
                consumer_id.0,
                REVIEW_CONTEXT_FIELDS.join(", ")
            )));
        }
    }
    Ok(())
}

/// Render a flat-namespace reference for diagnostics: `<head>[.<seg>..]`, each
/// step in the spelling an author must actually use (see [`access`]).
fn render_head_reference(head: &str, path: &[String]) -> String {
    let mut rendered = head.to_string();
    for segment in path {
        rendered.push_str(&access(segment));
    }
    rendered
}

/// Descend a `{{ stages.<producer>.parsed[.<path>] }}` reference's path against a
/// producer's rich `output_schema`, returning `Err` on a dangling segment or a
/// cross-stage type mismatch. A whole-envelope reference (empty path) is
/// existence-only (the producer exists — already checked by the caller).
fn check_reference_against_schema(
    consumer_id: &StageId,
    consumer: &ExecutionProgramStage,
    reference: &OutputReference,
    schema: &serde_json::Value,
    rendered: &str,
) -> KataResult<()> {
    let OutputReference { producer, path } = reference;
    // Whole-envelope: existence-only (a controller consuming the entire upstream
    // `parsed` envelope is legitimate). Do not descend.
    let Some((first, rest)) = path.split_first() else {
        return Ok(());
    };
    let Some(props) = schema.get("properties").and_then(|p| p.as_object()) else {
        // No `properties` node — an unusual/degenerate schema; skip conservatively.
        return Ok(());
    };
    let Some(first_node) = props.get(first.as_str()) else {
        let mut declared = props.keys().map(String::as_str).collect::<Vec<_>>();
        declared.sort_unstable();
        return Err(KataError::Validation(format!(
            "stage \"{}\" prompt references {{{{ {rendered} }}}} \
             but producer stage \"{producer}\" declares no contract field \"{first}\" \
             (declared contract fields: {}) — fix the field name or the \
             `produces=contract(..)` (dangling structured-output reference, \
             load-time check)",
            consumer_id.0,
            declared.join(", ")
        )));
    };
    // Cross-stage TYPE check on the FIRST segment: when the consumer
    // declares an input contract (`consumes=contract(..)`) that NAMES this field,
    // upgrade the existence check to an `is_subtype` check (the same
    // soundness-critical relation the cross-stage consumes/produces checker uses).
    if let Some(consumer_field) = consumer
        .input_schema
        .as_ref()
        .and_then(|s| s.get("properties"))
        .and_then(|p| p.as_object())
        .and_then(|p| p.get(first.as_str()))
        && !crate::dsl::schema::is_subtype(first_node, consumer_field)
    {
        return Err(KataError::Validation(format!(
            "stage \"{}\" prompt references {{{{ {rendered} }}}}: \
             producer stage \"{producer}\" emits \"{first}\" with a type that is NOT a \
             subtype of consumer stage \"{}\"'s declared `consumes=` input type for \
             \"{first}\" (cross-stage type mismatch, load-time check)",
            consumer_id.0, consumer_id.0
        )));
    }
    // Descend the remaining segments property-by-property. Each further segment
    // requires the CURRENT node be an object schema declaring that property; a
    // non-object node (array / variant / leaf) STOPS the walk conservatively.
    let mut node = first_node;
    let mut walked = vec![first.clone()];
    for segment in rest {
        let Some(node_props) = node.get("properties").and_then(|p| p.as_object()) else {
            // Not an object schema (array / variant / leaf, or the runtime `json`
            // free-form node): descend no further — nested access into a value is
            // out of scope for the schema walk.
            break;
        };
        if node.get("type").and_then(|t| t.as_str()) != Some("object") {
            break;
        }
        let Some(next_node) = node_props.get(segment.as_str()) else {
            let mut declared = node_props.keys().map(String::as_str).collect::<Vec<_>>();
            declared.sort_unstable();
            return Err(KataError::Validation(format!(
                "stage \"{}\" prompt references {{{{ {rendered} }}}} \
                 but producer stage \"{producer}\" declares no nested field \"{segment}\" \
                 under \"{}\" (declared nested fields: {}) — fix the field name or the \
                 `produces=contract(..)` (dangling structured-output reference, \
                 load-time check)",
                consumer_id.0,
                walked.join("."),
                declared.join(", ")
            )));
        };
        walked.push(segment.clone());
        node = next_node;
    }
    Ok(())
}

/// A `stages.<producer>.parsed[.<seg>..]` template reference, generalized from a
/// single field to a dotted PATH (whole-envelope + nested checking).
///
/// `path` is the sequence of `.<ident>` segments AFTER `.parsed`:
/// * `{{ stages.x.parsed }}`        → `path = []`   (whole-envelope reference)
/// * `{{ stages.x.parsed.a }}`      → `path = ["a"]`
/// * `{{ stages.x.parsed.a.b.c }}`  → `path = ["a", "b", "c"]`
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct OutputReference {
    pub(super) producer: String,
    pub(super) path: Vec<String>,
}

impl OutputReference {
    /// Render the reference as it appears in a template, for diagnostics:
    /// `stages.<producer>.parsed[.<seg>..]`.
    ///
    /// A producer or segment that is not a bare identifier is rendered in its
    /// only legal spelling — `stages["my-stage"].parsed` — so the diagnostic
    /// stays copy-pasteable back into the pack.
    fn render(&self) -> String {
        let mut rendered = format!("stages{}.parsed", access(&self.producer));
        for segment in &self.path {
            rendered.push_str(&access(segment));
        }
        rendered
    }
}

/// Render one access step in the spelling an author must actually use:
/// `.field` for a bare identifier, `["field"]` otherwise.
fn access(segment: &str) -> String {
    if !segment.is_empty() && segment.bytes().all(is_ident_byte) {
        format!(".{segment}")
    } else {
        format!("[{segment:?}]")
    }
}

/// Tolerant extractor for `stages.<ident>.parsed.<ident>` references that appear
/// inside a minijinja expression block (`{{ ... }}`) of a prompt template.
///
/// Conservative by construction:
/// * Only text INSIDE `{{ ... }}` is scanned. Prose and comments (`{# ... #}`)
///   are genuinely not render contexts, so a `stages.x.parsed.y` mention there
///   is correctly ignored.
///
///   **KNOWN GAP — statement blocks.** `{% if stages.x.parsed.y %}`,
///   `{% for i in stages.x.parsed.items %}` and `{% set v = stages.x.parsed.y %}`
///   ARE evaluated against the same context under `UndefinedBehavior::Strict`,
///   so a typo in one really does blow up at first render. They are not scanned
///   here, which makes such a reference a FALSE NEGATIVE (silently unchecked) —
///   the safe direction, but a gap, not a correctness property. Closing it needs
///   more than widening the scan: `{% set %}` can REBIND `stages`, and a
///   `{% for stages in … %}` loop variable shadows the namespace, so a naive
///   widening would hard-reject valid packs. Until that analysis exists the gap
///   stays open deliberately.
/// * Comment regions (`{# ... #}`) are skipped FIRST, before locating `{{`, so a
///   `{# {{ stages.x.parsed.y }} #}` (an expression block commented out) is not
///   scanned — minijinja renders nothing for it, so flagging it would be a false
///   positive.
/// * Inside a block, string-literal spans (`"..."` / `'...'`) are skipped, so a
///   `{{ "stages.x.parsed.y" }}` (the path is literal text, not a data render)
///   is not matched — likewise a false positive otherwise.
/// * The path `stages.<ident>.parsed[.<ident>..]` is matched with `<ident>`
///   restricted to `[A-Za-z0-9_]+`. After `.parsed` the extractor GREEDILY
///   consumes every further segment into the reference PATH, stopping at a `|`
///   filter, whitespace, a COMPUTED index, or a `.` not followed by an
///   identifier byte.
/// * Both spellings minijinja resolves identically are accepted, for the
///   producer and for every path segment: `.<ident>` and `["<literal>"]` /
///   `['<literal>']`. Brackets are not merely stylistic — a stage id that is not
///   a bare identifier (`my-stage`) is UNREACHABLE by dotted access, so
///   `stages["my-stage"].parsed.x` is the only legal way to write it. A COMPUTED
///   index (`stages[name]`, `parsed[key]`) names nothing statically known and is
///   deliberately left unextracted.
///
///   **KNOWN GAP — the `parsed` selector ITSELF is exempt from that acceptance.**
///   `.parsed` is matched in dotted form only (the `take_literal(…, ".parsed")`
///   below), so `stages.a['parsed'].nope` extracts nothing and compiles clean
///   even though minijinja resolves it identically to `stages.a.parsed.nope`.
///   VERIFIED through the production check path, not a standalone probe:
///   `kata workflows check` on a pack whose consumer reads
///   `{{ stages.producer['parsed'].nope }}` against a producer declaring only
///   `value` exits **0**. This is a FALSE NEGATIVE — the safe
///   direction, and the same class the bracket-spelling fix closed, one segment
///   over. It is left open rather than fixed because, unlike a hyphenated stage
///   id, `parsed` is ALWAYS a bare identifier, so the bracket spelling is never
///   *required* to reach it — nobody is forced to write the unchecked form. The
///   fix is mechanical (route `.parsed` through the same bracket-aware helper the
///   producer and path segments use); the reason to weigh it carefully is that
///   this file's hard-error path must never false-positive on a valid pack.
/// * `stages.x.parsed` with no trailing field IS matched (whole-envelope
///   reference, `path = []`): the producer's existence is checked, so a
///   whole-envelope reference to an unknown producer is caught. `parsed` must be
///   a COMPLETE segment — `stages.x.parsedX` (a longer identifier) is not a
///   match. `stages.x.content` and any non-`parsed` middle segment are not
///   matched.
pub(super) fn extract_parsed_output_references(template: &str) -> Vec<OutputReference> {
    let mut refs = Vec::new();
    for_each_expression_block(template, |block| {
        scan_block_for_parsed_refs(block, &mut refs);
    });
    refs
}

/// Extract every `{{ <head>[.<seg>..] }}` reference's dotted path (the
/// segments AFTER the top-level `<head>` variable) from a template's expression
/// blocks. Honors the SAME comment / string-literal / word-boundary guards as
/// [`extract_parsed_output_references`], and — critically — matches `<head>` only
/// as a TOP-LEVEL variable: a `<head>` preceded by `.` (a field access on another
/// object, e.g. the stage name in `stages.review.parsed`) is NOT a match. An
/// empty returned path is a whole-namespace reference (`{{ <head> }}`).
pub(crate) fn extract_head_references(template: &str, head: &str) -> Vec<Vec<String>> {
    let mut refs = Vec::new();
    for_each_expression_block(template, |block| {
        scan_block_for_head_refs(block, head, &mut refs);
    });
    refs
}

/// Invoke `visit` once per `{{ ... }}` expression-block BODY in `template`,
/// skipping `{# ... #}` comment regions and `{% raw %} … {% endraw %}` regions
/// wholesale (a `{{ }}` nested inside either is never rendered, so it is never
/// visited). Shared by the `stages.*.parsed` and flat-namespace
/// (`external_inputs.*` / `review.*`) extractors so all three scan an identical
/// block set.
///
/// Statement tags (`{% if %}` / `{% for %}` / `{% set %}` / …) are stepped OVER
/// rather than visited — see the module-level KNOWN GAP note. Only the `raw`
/// family is special, because it suppresses rendering of everything up to its
/// matching `endraw`.
fn for_each_expression_block(template: &str, mut visit: impl FnMut(&str)) {
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let next_expr = template[i..].find("{{").map(|rel| i + rel);
        let next_comment = template[i..].find("{#").map(|rel| i + rel);
        let next_stmt = template[i..].find("{%").map(|rel| i + rel);
        let Some(pos) = [next_expr, next_comment, next_stmt]
            .into_iter()
            .flatten()
            .min()
        else {
            break;
        };
        if next_comment == Some(pos) {
            // Skip the whole `{# ... #}` region so any `{{ }}` nested inside it
            // is never scanned.
            let body = pos + 2;
            let end = template[body..]
                .find("#}")
                .map_or(bytes.len(), |rel| body + rel + 2);
            i = end.max(pos + 2);
        } else if next_stmt == Some(pos) {
            let (tag, after_tag) = statement_tag_at(template, pos);
            i = if tag_keyword_is(&tag, "raw") {
                // minijinja emits a raw region's body VERBATIM. Skipping to the
                // matching `endraw` keeps a reference spelled inside it from
                // being read as a live data dependency (it is literal text).
                skip_to_endraw(template, after_tag)
            } else {
                after_tag.max(pos + 2)
            };
        } else {
            let block_start = pos + 2;
            // Find the matching `}}`; if unterminated, scan to end of string
            // (a malformed template fails the render later, but extracting
            // refs from the trailing bytes stays conservative).
            let block_end = template[block_start..]
                .find("}}")
                .map_or(bytes.len(), |rel| block_start + rel);
            visit(&template[block_start..block_end]);
            i = if block_end >= bytes.len() {
                bytes.len()
            } else {
                block_end + 2
            };
        }
    }
}

/// Split the `{% ... %}` statement tag opening at `pos`, returning its trimmed
/// body (with minijinja's `-` whitespace-control markers stripped) and the
/// offset just past the closing `%}`. An unterminated tag yields everything to
/// end-of-string.
fn statement_tag_at(template: &str, pos: usize) -> (String, usize) {
    let body = pos + 2;
    let tag_end = template[body..]
        .find("%}")
        .map_or(template.len(), |rel| body + rel);
    let tag = template[body..tag_end]
        .trim()
        .trim_start_matches('-')
        .trim_end_matches('-')
        .trim()
        .to_owned();
    let after = if tag_end >= template.len() {
        template.len()
    } else {
        tag_end + 2
    };
    (tag, after)
}

/// True when a statement tag's FIRST word is `keyword` (so `raw` matches but a
/// user block named `rawdata` does not).
fn tag_keyword_is(tag: &str, keyword: &str) -> bool {
    tag.split_whitespace().next() == Some(keyword)
}

/// Offset just past the `{% endraw %}` closing the raw region that starts at
/// `from`. An UNTERMINATED raw region swallows the rest of the template — the
/// conservative direction, since an unclosed `raw` fails to parse at render
/// anyway and extracting no reference can never false-positive.
fn skip_to_endraw(template: &str, from: usize) -> usize {
    let mut i = from;
    while let Some(rel) = template[i..].find("{%") {
        let open = i + rel;
        let (tag, after) = statement_tag_at(template, open);
        if tag_keyword_is(&tag, "endraw") {
            return after;
        }
        i = after.max(open + 2);
    }
    template.len()
}

/// Scan one `{{ ... }}` block body for a TOP-LEVEL `<head>[.<seg>..]` reference,
/// skipping `"..."` / `'...'` string-literal spans (a quoted head is literal
/// text, not a data render). `<head>` matches only as the start of a
/// variable-access chain: the byte before must be neither an identifier byte NOR
/// a `.` — a leading `.` means `<head>` is a field of another object (e.g. the
/// `review` in `stages.review.parsed`), not the top-level namespace.
fn scan_block_for_head_refs(block: &str, head: &str, refs: &mut Vec<Vec<String>>) {
    let bytes = block.as_bytes();
    let mut pos = 0;
    while pos < bytes.len() {
        match bytes[pos] {
            quote @ (b'"' | b'\'') => {
                pos += 1;
                while pos < bytes.len() {
                    if bytes[pos] == b'\\' {
                        pos += 2;
                        continue;
                    }
                    if bytes[pos] == quote {
                        pos += 1;
                        break;
                    }
                    pos += 1;
                }
            }
            _ => {
                if block[pos..].starts_with(head) {
                    let boundary_before =
                        pos == 0 || (!is_ident_byte(bytes[pos - 1]) && bytes[pos - 1] != b'.');
                    let mut cursor = pos + head.len();
                    // `<head>` must be a COMPLETE identifier: the next byte must
                    // not be an identifier byte (else `review` matched `reviewer`,
                    // or `external_inputs` matched a longer identifier).
                    if boundary_before && !next_is_ident_byte(bytes, cursor) {
                        refs.push(take_path_segments(bytes, &mut cursor));
                    }
                    pos += head.len();
                } else {
                    pos += 1;
                }
            }
        }
    }
}

/// Scan one `{{ ... }}` expression-block body for `stages.<id>.parsed.<field>`
/// dotted paths, skipping any `"..."` / `'...'` string-literal spans (a quoted
/// `stages.x.parsed.y` is literal text, not a data render).
fn scan_block_for_parsed_refs(block: &str, refs: &mut Vec<OutputReference>) {
    let bytes = block.as_bytes();
    let mut pos = 0;
    while pos < bytes.len() {
        match bytes[pos] {
            // Skip a string literal wholesale (honoring `\`-escapes), so its
            // contents are never matched as a path.
            quote @ (b'"' | b'\'') => {
                pos += 1;
                while pos < bytes.len() {
                    if bytes[pos] == b'\\' {
                        pos += 2;
                        continue;
                    }
                    if bytes[pos] == quote {
                        pos += 1;
                        break;
                    }
                    pos += 1;
                }
            }
            _ => {
                if block[pos..].starts_with("stages") {
                    // `stages` must be a path head, not the tail of a longer
                    // identifier (e.g. `my_stages.x`): the char before must not
                    // be an identifier byte.
                    let is_word_boundary = pos == 0 || !is_ident_byte(bytes[pos - 1]);
                    let mut cursor = pos + "stages".len();
                    if is_word_boundary
                        && let Some(producer) = take_producer(bytes, &mut cursor)
                        && take_literal(bytes, &mut cursor, ".parsed")
                        // `.parsed` must be a COMPLETE segment: the next byte must
                        // not be an identifier byte (else the real identifier was
                        // e.g. `parsedX`/`parsed_foo`, not `parsed`).
                        && !next_is_ident_byte(bytes, cursor)
                    {
                        // Greedily consume every further `.<ident>` or
                        // `["<literal>"]` segment into the reference path. Stops
                        // at `|`, whitespace, a COMPUTED index, or a `.` not
                        // followed by an identifier byte.
                        let path = take_path_segments(bytes, &mut cursor);
                        refs.push(OutputReference { producer, path });
                    }
                    pos += "stages".len();
                } else {
                    pos += 1;
                }
            }
        }
    }
}

/// Consume a maximal `[A-Za-z0-9_]+` identifier at `*cursor`, advancing the
/// cursor past it. Returns `None` (cursor unchanged) when no identifier byte is
/// present.
fn take_ident(bytes: &[u8], cursor: &mut usize) -> Option<String> {
    let start = *cursor;
    while *cursor < bytes.len() && is_ident_byte(bytes[*cursor]) {
        *cursor += 1;
    }
    if *cursor == start {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes[start..*cursor]).into_owned())
}

/// Consume the PRODUCER selector immediately after the `stages` head, in either
/// spelling minijinja resolves identically:
///
/// * `.<ident>`      — `stages.draft`
/// * `["<literal>"]` — `stages["my-stage"]` / `stages['my-stage']`
///
/// The bracket spelling is not a stylistic alternative: a stage id that is not a
/// bare identifier (`my-stage`, `plan.v2`) CANNOT be reached with dotted access
/// at all, so brackets are the only legal way to reference it.
///
/// A COMPUTED index (`stages[name]`, `stages[loop.index]`) names no statically
/// known producer, so it is deliberately not consumed — the reference is left
/// unextracted rather than guessed at.
fn take_producer(bytes: &[u8], cursor: &mut usize) -> Option<String> {
    if *cursor < bytes.len() && bytes[*cursor] == b'.' {
        let mut probe = *cursor + 1;
        let ident = take_ident(bytes, &mut probe)?;
        *cursor = probe;
        return Some(ident);
    }
    take_bracket_literal(bytes, cursor)
}

/// Greedily consume a run of path segments at `*cursor`, in either spelling:
/// `.<ident>` or `["<literal>"]` / `['<literal>']`. Returns them in order,
/// leaving the cursor at the first byte that starts neither (a `|` filter, a
/// COMPUTED index, whitespace, `}`, EOF, or a `.` followed by a non-identifier).
///
/// minijinja resolves `parsed.field` and `parsed["field"]` to the same lookup on
/// a JSON object, so both must contribute the same path segment — otherwise the
/// bracket spelling silently degrades to a whole-envelope reference and its
/// field goes unchecked.
fn take_path_segments(bytes: &[u8], cursor: &mut usize) -> Vec<String> {
    let mut path = Vec::new();
    loop {
        if *cursor < bytes.len() && bytes[*cursor] == b'.' && next_is_ident_byte(bytes, *cursor + 1)
        {
            *cursor += 1; // consume the '.'
            let Some(segment) = take_ident(bytes, cursor) else {
                break;
            };
            path.push(segment);
        } else if let Some(segment) = take_bracket_literal(bytes, cursor) {
            path.push(segment);
        } else {
            break;
        }
    }
    path
}

/// Consume a `["<literal>"]` / `['<literal>']` bracket index at `*cursor`,
/// advancing past the closing `]` on success. Returns `None` with the cursor
/// UNCHANGED for anything else — a computed index, an empty literal, a
/// backslash-escaped literal (whose decoded value this scanner does not model),
/// or a missing bracket. Every rejection leaves the reference unextracted, which
/// is the false-NEGATIVE (safe) direction.
fn take_bracket_literal(bytes: &[u8], cursor: &mut usize) -> Option<String> {
    let mut probe = *cursor;
    if probe >= bytes.len() || bytes[probe] != b'[' {
        return None;
    }
    probe += 1;
    let quote = *bytes.get(probe)?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    probe += 1;
    let start = probe;
    while probe < bytes.len() && bytes[probe] != quote {
        // A `\`-escape means the literal's decoded value differs from its source
        // bytes; refuse rather than mis-model it.
        if bytes[probe] == b'\\' {
            return None;
        }
        probe += 1;
    }
    if probe >= bytes.len() || probe == start {
        return None;
    }
    let literal = String::from_utf8_lossy(&bytes[start..probe]).into_owned();
    probe += 1; // closing quote
    if probe >= bytes.len() || bytes[probe] != b']' {
        return None;
    }
    probe += 1; // closing ']'
    *cursor = probe;
    Some(literal)
}

/// True when `pos` is in bounds and `bytes[pos]` is an identifier byte.
fn next_is_ident_byte(bytes: &[u8], pos: usize) -> bool {
    pos < bytes.len() && is_ident_byte(bytes[pos])
}

/// Consume an exact literal at `*cursor`, advancing past it on a match. Leaves
/// the cursor unchanged and returns `false` otherwise.
fn take_literal(bytes: &[u8], cursor: &mut usize, literal: &str) -> bool {
    if *cursor <= bytes.len() && bytes[*cursor..].starts_with(literal.as_bytes()) {
        *cursor += literal.len();
        true
    } else {
        false
    }
}

const fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}
