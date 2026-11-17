//! DECLARE + DERIVE + REFUSE ON MISMATCH.
//!
//! # Why this test exists, and what its RED had to be
//!
//! The derivation can move under an unchanged pack: re-keying a sandbox knob
//! (for example making a read-only host mount derive `Nondeterministic`) is a
//! CORRECT change in which no authored line moves, so without a declaration a
//! stage silently leaves the content cache and `kata workflows check` still
//! exits 0. An authored `execution_requirements=` determinism claim is the
//! author's statement that pins the class, and compile must refuse when the
//! derivation disagrees with it.
//!
//! The RED this test guards is taken with the `execution_requirements=` surface
//! fully present and only the compile check absent. It is therefore not
//! "unknown keyword" — the keyword parses, type-checks and reaches
//! `StageDefinition` — it is:
//!
//! ```text
//! a declaration that disagrees with the derivation was ACCEPTED (compile
//! returned Ok) — the declaration is a comment
//! ```
//!
//! That is the silent-flip defect reproduced under the declaration surface itself, which
//! is the only RED that proves the check is load-bearing. A test that failed on
//! the keyword's absence would have proven the keyword exists and nothing more.

use kata_program::execution_program::compile_starlark_execution_program;

const FIXTURE: &str = include_str!("fixtures/declared-determinism-shell.star");

#[test]
fn a_declared_determinism_claim_refuses_when_the_derivation_moves_under_it() {
    let error = compile_starlark_execution_program(FIXTURE, "declared-determinism-shell.star", &[])
        .expect_err(
            "a declaration that disagrees with the derivation was ACCEPTED (compile returned Ok) \
         — the declaration is a comment",
        );
    let message = format!("{error}");

    for needle in [
        "probe",
        "determinism",
        "deterministic",
        "nondeterministic",
        "execution_requirements",
    ] {
        assert!(
            message.contains(needle),
            "the mismatch refusal must name {needle:?} so an author can act on it; got: {message}"
        );
    }
}

/// The other half of the refused set: a declaration that AGREES is admitted.
///
/// Without this, the check above would pass just as well if the compiler refused
/// every declaration — which is a guarantee wider than its mechanism, and the
/// defect this corpus finds most often.
#[test]
fn a_declaration_that_agrees_with_the_derivation_is_admitted() {
    let source = FIXTURE.replace(
        r#"{"determinism": "deterministic"}"#,
        r#"{"determinism": "nondeterministic"}"#,
    );
    assert_ne!(source, FIXTURE, "the fixture's declaration spelling moved");
    compile_starlark_execution_program(&source, "agrees.star", &[])
        .expect("a declaration matching the derivation must be admitted");
}

/// A model stage declaring `network = "offline"`, under each `net` spelling and
/// under the materialized default (no `sandbox=`).
fn model_stage_declaring_offline(sandbox: &str) -> String {
    format!(
        "probe = stage(id = \"probe\", agent = \"default\", prompt = \"x\",{sandbox} \
         execution_requirements = {{\"network\": \"offline\"}})\n\
         workflow(\"declared-offline-model\", root = [probe])\n"
    )
}

/// **The refused set of a declared `network = "offline"` on a MODEL stage is
/// every such stage, whatever `net` says.** A model stage's network axis is
/// derived `unrestricted` under either spelling (its turn talks to its model
/// provider from the process hosting the worker, whatever the capsule's `net`),
/// so the declaration can never agree: the refusal says so and names the one fix
/// that exists — the declaration, not the stage.
///
/// One case per refused shape: `net = "offline"` (admitted before the class
/// stopped claiming an offline model stage — the shape this cell's RED was taken
/// on), `net = "host"`, and no `sandbox=` (the materialized model default).
#[test]
fn a_model_stage_declaring_an_offline_network_is_refused_under_every_net() {
    for (shape, sandbox) in [
        (
            "net = offline",
            " sandbox = sandbox_profile(net = \"offline\"),",
        ),
        ("net = host", " sandbox = sandbox_profile(net = \"host\"),"),
        ("no sandbox=", ""),
    ] {
        let source = model_stage_declaring_offline(sandbox);
        let error = compile_starlark_execution_program(&source, "declared-offline-model.star", &[])
            .expect_err(&format!(
                "{shape}: a model stage's declared offline network was ADMITTED — the class \
                 would claim an offline network its capsule does not get"
            ));
        let message = format!("{error}");
        for needle in [
            "probe",
            "network=\"offline\"",
            "network=\"unrestricted\"",
            "A model stage's network is derived unrestricted under either `net`",
            "change the declaration to \"unrestricted\" or drop the key",
        ] {
            assert!(
                message.contains(needle),
                "{shape}: the refusal must say {needle:?}; got: {message}"
            );
        }
    }
}

/// The admitted half: a SHELL stage under `net = "offline"` declaring
/// `network = "offline"` agrees with its derivation, and a model stage
/// declaring `network = "unrestricted"` under `net = "offline"` agrees with
/// its own.
#[test]
fn an_offline_network_declaration_that_agrees_is_admitted() {
    let shell = "probe = stage(id = \"probe\", agent = \"shell\", run = \"true\", \
         sandbox = sandbox_profile(net = \"offline\"), \
         execution_requirements = {\"network\": \"offline\"})\n\
         workflow(\"declared-offline-shell\", root = [probe])\n";
    compile_starlark_execution_program(shell, "declared-offline-shell.star", &[])
        .expect("a shell stage under net=offline is offline, as declared");
    let model = model_stage_declaring_offline(" sandbox = sandbox_profile(net = \"offline\"),")
        .replace(
            "{\"network\": \"offline\"}",
            "{\"network\": \"unrestricted\"}",
        );
    compile_starlark_execution_program(&model, "declared-unrestricted-model.star", &[])
        .expect("a model stage declaring the network its class derives is admitted");
}
