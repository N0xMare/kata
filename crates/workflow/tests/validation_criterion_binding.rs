//! A validation criterion is bound to its proof stage by DECLARATION.
//!
//! The binding is never reconstructed from a stage NAME. A name convention (a
//! completed stage's output counting as validation evidence only when its base name
//! is `validate`, `validation`, or `*_validate`) would not make X a validation stage
//! for `validation_criterion(stage = X)`, so four unprovable-criterion shapes would
//! load-check clean and fail only at the promotion gate — or, on the in-graph
//! `promote` arm, not fail at all:
//!
//!   1. an INELIGIBLE BACKEND — a model stage (which would self-certify its own
//!      promotion) or a `workspace_effect` stage (which emits a park/promote
//!      envelope and never a report);
//!   2. a stage whose NAME fails the convention (`check`, `gate_run`, …), which
//!      would be permanently unprovable however it was declared;
//!   3. the `stage` field UNSET entirely — an `if let Some(stage)` arm would
//!      simply skip it;
//!   4. a criterion naming a stage that cannot produce evidence.
//!
//! Each test below pins ONE of those, and the file also pins the shape the
//! refusals must NOT touch. Shape 4 has no test here on purpose: see
//! [`shape_four_is_a_runtime_property_and_this_file_says_so`].

use std::path::PathBuf;

use kata_program::execution_program::compile_starlark_execution_program;

/// Compile inline Starlark through the SAME entry point `kata workflows check`
/// reaches (`parser::validate` → `compile_execution_program*`), so a test that
/// says "refused at load" is measuring the load path and not a helper.
fn load(source: &str) -> Result<kata_program::execution_program::ExecutionProgram, String> {
    let roots: Vec<PathBuf> = Vec::new();
    compile_starlark_execution_program(source, "binding-probe.star", &roots)
        .map_err(|error| error.to_string())
}

/// A `shell` proof stage named `validate`, a required criterion bound to it.
/// The shape that was already correct, kept as the control for every refusal.
const CONTROL: &str = r#"
validate = stage(
    id = "validate",
    agent = "shell",
    run = "printf '{\"status\":\"passed\"}\\n'",
)
workflow(
    "control",
    description = "Control: a required criterion on a proof-eligible shell stage.",
    root = [validate],
    validation_criteria = [
        validation_criterion(
            "c1",
            description = "The deterministic check passes.",
            stage = "validate",
            commands = ["true"],
            required = True,
        ),
    ],
)
"#;

#[test]
fn the_control_shape_still_loads() {
    let program = load(CONTROL).expect("the already-correct shape must keep loading");
    assert!(program.stage_records_validation_evidence("validate"));
}

// ── SHAPE 1: an ineligible backend ──────────────────────────────────────────

/// SHAPE 1a. A criterion bound to a MODEL stage is refused at compile. Measured
/// before the guard: `kata workflows check` exited 0 with `verifier=warn`, and
/// the criterion then failed the promotion gate with `proof_stage_not_deterministic`
/// after an execution id had been minted and durable rows written.
#[test]
fn criterion_on_a_model_proof_stage_is_refused_at_load() {
    let source = r#"
validate = stage(
    id = "validate",
    agent = "codex",
    sandbox = "verdict",
    prompt = "emit a verdict",
)
workflow(
    "model-proof-stage",
    description = "A criterion bound to a model stage.",
    root = [validate],
    validation_criteria = [
        validation_criterion(
            "c1",
            description = "An LLM may not certify its own promotion.",
            stage = "validate",
            required = True,
        ),
    ],
    sandbox_profiles = {
        "verdict": sandbox_profile(net = "host"),
    },
)
"#;
    let error = load(source).expect_err("a model proof stage must be refused at load");
    assert!(
        error.contains("declares proof stage \"validate\"")
            && error.contains("backend \"codex\"")
            && error.contains("may not be trusted with a validation verdict"),
        "refusal must name the criterion, the stage and the backend: {error}"
    );
}

/// SHAPE 1b. A `workspace_effect` stage is DETERMINISTIC yet still ineligible:
/// it emits `{operation, ref_name, commit_sha}` and never a validation report.
/// This is the arm that proves the guard keys on
/// `is_validation_proof_eligible` and not on raw determinism.
#[test]
fn criterion_on_a_workspace_effect_proof_stage_is_refused_at_load() {
    let source = r#"
seed = stage(
    id = "seed",
    agent = "shell",
    run = "printf '{\"ok\":true}\\n'",
    outputs = {"ok": "bool"},
)
validate = stage(
    id = "validate",
    agent = "workspace_effect",
    op = "commit",
    label = "record",
    depends_on = ["seed"],
)
workflow(
    "effect-proof-stage",
    description = "A criterion bound to a workspace_effect stage.",
    root = [seed, validate],
    worktree_isolated = True,
    validation_criteria = [
        validation_criterion(
            "c1",
            description = "An effect stage emits no report.",
            stage = "validate",
            required = True,
        ),
    ],
)
"#;
    let error = load(source).expect_err("a workspace_effect proof stage must be refused at load");
    assert!(
        error.contains("backend \"workspace_effect\"")
            && error.contains("never a validation report"),
        "refusal must name the effect backend and why it cannot carry a verdict: {error}"
    );
}

/// The eligibility guard covers OPTIONAL criteria too. `validation_criteria_gate`
/// ignores a non-`required` criterion, so this one gates nothing — but under the
/// declaration binding a criterion is what makes its stage RECORD validation
/// evidence, so admitting it would route model output into the validation plane.
/// Refusing here keeps the recording set and the trusted set the same set. This
/// is the arm that cost `workflows/kata-factory/kata/factory.star` four
/// declarations.
#[test]
fn an_optional_criterion_on_an_ineligible_stage_is_refused_too() {
    let source = r#"
validate = stage(
    id = "validate",
    agent = "shell",
    run = "printf '{\"status\":\"passed\"}\\n'",
)
controller = stage(
    id = "controller",
    agent = "codex",
    sandbox = "verdict",
    depends_on = ["validate"],
    prompt = "decide",
)
workflow(
    "optional-on-model",
    description = "An OPTIONAL criterion bound to a model controller.",
    root = [validate, controller],
    validation_criteria = [
        validation_criterion(
            "c1",
            description = "The deterministic check passes.",
            stage = "validate",
            required = True,
        ),
        validation_criterion(
            "controller-decision",
            description = "The controller recorded a decision.",
            stage = "controller",
            required = False,
        ),
    ],
    sandbox_profiles = {
        "verdict": sandbox_profile(net = "host"),
    },
)
"#;
    let error = load(source).expect_err("an optional criterion on a model stage must be refused");
    assert!(
        error.contains("criterion \"controller-decision\"") && error.contains("backend \"codex\""),
        "refusal must name the OPTIONAL criterion, not silently skip it: {error}"
    );
}

// ── SHAPE 2: the name convention ────────────────────────────────────────────

/// SHAPE 2, INVERTED: a criterion declared on a proof-eligible stage named
/// `check` is admitted AND binds, because the declaration is the binding. Under
/// a stage-name convention this pack would load clean, run its check, emit a
/// passing report, and then never be promoted.
///
/// The second half is the load-bearing one: `check` RECORDS and the
/// conventionally-named `validate` — which no criterion declares — does NOT.
/// That is the exact inversion of a name rule, in one assertion pair.
#[test]
fn criterion_on_an_unconventionally_named_stage_loads_and_binds() {
    let source = r#"
check = stage(
    id = "check",
    agent = "shell",
    run = "printf '{\"status\":\"passed\"}\\n'",
)
validate = stage(
    id = "validate",
    agent = "shell",
    depends_on = ["check"],
    run = "printf '{\"status\":\"passed\"}\\n'",
)
workflow(
    "unconventional-proof-stage",
    description = "A criterion declared on a stage no name convention recognizes.",
    root = [check, validate],
    validation_criteria = [
        validation_criterion(
            "gate-green",
            description = "The check exits 0.",
            stage = "check",
            commands = ["true"],
            required = True,
        ),
    ],
)
"#;
    let program = load(source).expect("an unconventionally named proof stage must load");
    assert!(
        program.stage_records_validation_evidence("check"),
        "the DECLARED proof stage must record, whatever it is called"
    );
    assert!(
        !program.stage_records_validation_evidence("validate"),
        "a stage the convention would have accepted but NO criterion declares must not record"
    );
}

/// The refused set of the recording rule, stated and proved. It is exactly:
/// every runtime stage whose checked base id — the part before the first `#` —
/// is not named by a declared
/// criterion. Synthetic invocation suffixes therefore still resolve, which is
/// what keeps a loop's `check#iter-2` and a retry's `check#iter-2#validate-1`
/// recording.
#[test]
fn recording_rule_refuses_exactly_the_stages_no_criterion_declares() {
    let program = load(CONTROL).expect("control loads");
    for records in [
        "validate",
        "validate#iter-2",
        "validate#iter-2#validate-1",
        "validate#child-0",
    ] {
        assert!(
            program.stage_records_validation_evidence(records),
            "the declared proof stage and its synthetic invocations must record: {records}"
        );
    }
    for refused in [
        "check",
        "validation",
        "gate_validate",
        "validate_all",
        "validated",
    ] {
        assert!(
            !program.stage_records_validation_evidence(refused),
            "a stage no criterion declares must not record: {refused}"
        );
    }
}

// ── SHAPE 3: the stage field unset ──────────────────────────────────────────

/// SHAPE 3. An unbound criterion is refused at the EARLIEST door
/// (`parser::validate`), because it is decidable from the criterion alone — no
/// stage map and no lowering. Before the guard it load-checked clean and then
/// blocked promotion forever with `proof_stage_unbound`.
#[test]
fn unbound_criterion_is_refused_at_load() {
    let source = r#"
validate = stage(
    id = "validate",
    agent = "shell",
    run = "printf '{\"status\":\"passed\"}\\n'",
)
workflow(
    "unbound-criterion",
    description = "A criterion with no proof stage at all.",
    root = [validate],
    validation_criteria = [
        validation_criterion(
            "c1",
            description = "Nothing proves this.",
            required = True,
        ),
    ],
)
"#;
    let error = load(source).expect_err("an unbound criterion must be refused at load");
    assert!(
        error.contains("criterion \"c1\" declares no proof stage")
            && error.contains("an unbound criterion can never be satisfied"),
        "refusal must say the binding is missing and that it is unsatisfiable: {error}"
    );
}

// ── SHAPE 4: not decidable here, and this file says why ─────────────────────

/// SHAPE 4 — "a criterion naming a stage that cannot produce evidence" — gets NO
/// load refusal, and that is a measurement, not an omission.
///
/// After shapes 1 and 3 are refused, every surviving criterion names a
/// proof-eligible `shell` stage. Whether such a stage produces a report is a
/// property of what its command PRINTS, and a declared output contract does not
/// bound it: `runner::json::validate_and_inject_parsed` is a presence + type
/// check that ADMITS EXTRA KEYS and injects the whole parsed object as `parsed`.
/// So the pack below — whose proof stage declares a closed-looking
/// `outputs = {"widget_count": "u32"}` — is admitted, and it is admitted
/// CORRECTLY: the same stage may print `status`/`criteria` alongside
/// `widget_count` and prove its criterion. `workflows/std/kata-gate-fix-loop.star`
/// relies on exactly that.
///
/// The gate's answer for a criterion that never receives evidence is
/// `validation_criterion:<id>:missing`, which is the honest label — a rerun
/// CAN produce the report.
#[test]
fn shape_four_is_a_runtime_property_and_this_file_says_so() {
    let source = r#"
validate = stage(
    id = "validate",
    agent = "shell",
    run = "printf '{\"widget_count\":3}\\n'",
    outputs = {"widget_count": "u32"},
)
workflow(
    "no-report-contract",
    description = "A proof stage whose declared contract carries no report fields.",
    root = [validate],
    validation_criteria = [
        validation_criterion(
            "c1",
            description = "Whether this is provable depends on what the command prints.",
            stage = "validate",
            commands = ["true"],
            required = True,
        ),
    ],
)
"#;
    let program = load(source).expect("a declared output contract does not bound the report");
    assert!(
        program.stage_records_validation_evidence("validate"),
        "the stage still records: the declared contract admits extra keys"
    );
}

// ── The in-graph promote arm ────────────────────────────────────────────────

const PROMOTE_PACK: &str = r#"
work = stage(
    id = "work",
    agent = "shell",
    run = "printf '{\"ok\":true}\\n'",
    outputs = {"ok": "bool"},
)
gate_run = stage(
    id = "gate_run",
    agent = "shell",
    depends_on = ["work"],
    run = "printf '{\"status\":\"passed\"}\\n'",
)
land = stage(
    id = "land",
    agent = "workspace_effect",
    op = "promote",
    label = "promote",
    depends_on = ["gate_run"],
)
workflow(
    "in-graph-promote",
    description = "A graph that lands on the operator base ref.",
    root = [work, gate_run, land],
    worktree_isolated = True,
    CRITERIA
)
"#;

/// `workflows/std/kata-gate-fix-loop.star`'s shape, reduced. A graph that
/// carries a `promote` and declares NO required criterion is refused at load.
///
/// The operator route already denied this program — but only after submit,
/// dispatch and (for a model loop) the expensive half of the run; and the
/// IN-GRAPH route, where a `branch` arm wires a controller verdict straight into
/// the effect stage, never consulted that gate at all. Whether the criterion is
/// SATISFIED is a runtime question; whether one EXISTS is decidable here.
#[test]
fn promote_without_a_required_criterion_is_refused_at_load() {
    let error = load(&PROMOTE_PACK.replace("CRITERIA", ""))
        .expect_err("a promote with no required criterion must be refused at load");
    assert!(
        error.contains("promote stage(s) \"land\"")
            && error.contains("no REQUIRED validation criterion"),
        "refusal must name the promote stage and what is missing: {error}"
    );
}

/// SCOPE FENCE for the promote refusal, in both directions: an OPTIONAL
/// criterion does not satisfy it (it gates nothing), and a required one does.
#[test]
fn promote_refusal_needs_a_required_criterion_not_merely_a_declared_one() {
    let optional = PROMOTE_PACK.replace(
        "CRITERIA",
        r#"validation_criteria = [
        validation_criterion(
            "gate-green",
            description = "advisory only",
            stage = "gate_run",
            required = False,
        ),
    ],"#,
    );
    let error =
        load(&optional).expect_err("an optional criterion must not satisfy the promote rule");
    assert!(
        error.contains("no REQUIRED validation criterion"),
        "the promote rule must key on `required`: {error}"
    );

    let required = PROMOTE_PACK.replace(
        "CRITERIA",
        r#"validation_criteria = [
        validation_criterion(
            "gate-green",
            description = "the deterministic gate exits 0",
            stage = "gate_run",
            commands = ["true"],
            required = True,
        ),
    ],"#,
    );
    let program = load(&required).expect("a required criterion admits the promote graph");
    assert!(program.stage_records_validation_evidence("gate_run"));
}

/// SCOPE FENCE the other way: the promote rule refuses `promote` and NOTHING
/// else. `park`, `commit` and `forge_export` do not land on the operator's base
/// ref, so a graph carrying only those keeps loading with no criteria at all —
/// which is what leaves the model-free effect smokes untouched.
#[test]
fn park_and_commit_graphs_are_not_touched_by_the_promote_refusal() {
    let source = r#"
work = stage(
    id = "work",
    agent = "shell",
    run = "printf '{\"ok\":true}\\n'",
    outputs = {"ok": "bool"},
)
record = stage(
    id = "record",
    agent = "workspace_effect",
    op = "commit",
    label = "record",
    depends_on = ["work"],
)
shelve = stage(
    id = "shelve",
    agent = "workspace_effect",
    op = "park",
    label = "blocked",
    depends_on = ["record"],
)
workflow(
    "park-and-commit",
    description = "Effects that never touch the operator base ref.",
    root = [work, record, shelve],
    worktree_isolated = True,
)
"#;
    let program = load(source).expect("park/commit graphs need no validation criteria");
    assert!(program.validation_criteria.criteria.is_empty());
}
