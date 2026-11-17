//! Bounded structural check that the LIVE (cost-spending) eval tier is absent from
//! the statically modelled `just gate` recipe graph.
//!
//! The deterministic tier (this crate's other tests + the `just eval` recipe)
//! rides the gate; the live tier (`just eval-live`) must not. It is gated behind
//! an explicit `KATA_EVAL_LIVE=1` spend acknowledgment and is invoked only by its
//! own recipe, which the modelled graph never calls. This is not a proof over
//! arbitrary shell or external scripts; an actual gate run is the execution receipt.
//!
//! It has since grown the other half of the same question — not "what must the
//! gate never run" but "what must the containment lane never STOP running". See
//! the CONTAINMENT COVERAGE section at the bottom.

mod common;

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    path::{Component, Path, PathBuf},
    sync::OnceLock,
};

use common::justfile::{
    DYNAMIC, Justfile, Recipe, calls_in_body, justfile_text, logical_lines, parse_justfile_source,
    reachable_recipes, recipe_body, resolved_recipe, structurally_required_recipes,
};
use common::nextest::{Filterset, negations_not_of_one_test_predicate, parse_filterset};
use common::rust_tree::{ModuleDirs, ModuleSource, SourceCache, module_source, root_dirs};
use common::{LIVE_CAPABILITY_MARKERS, repo_root};

#[test]
fn reachability_includes_header_dependencies() {
    let justfile = parse_justfile_source("root: proof\n\techo root\n\nproof:\n\techo proof\n");
    let reachable = reachable_recipes(&justfile, "root");
    assert!(reachable.contains_key("proof"), "reachable: {reachable:?}");
}

#[test]
fn reachability_follows_every_literal_call_on_a_line() {
    let justfile = parse_justfile_source(
        "root:\n\tjust first; just second\n\nfirst:\n\techo first\n\nsecond:\n\techo second\n",
    );
    let reachable = reachable_recipes(&justfile, "root");
    assert!(reachable.contains_key("first"), "reachable: {reachable:?}");
    assert!(reachable.contains_key("second"), "reachable: {reachable:?}");
}

#[test]
fn reachability_does_not_treat_quoted_echo_text_as_a_call() {
    let justfile =
        parse_justfile_source("root:\n\techo \"run just proof\"\n\nproof:\n\techo proof\n");
    let reachable = reachable_recipes(&justfile, "root");
    assert!(!reachable.contains_key("proof"), "reachable: {reachable:?}");
}

#[test]
fn reachability_refuses_a_dynamic_recipe_name() {
    let justfile = parse_justfile_source(
        "root:\n\trecipe=proof\n\tjust \"$recipe\"\n\nproof:\n\techo proof\n",
    );
    let failure = std::panic::catch_unwind(|| reachable_recipes(&justfile, "root"))
        .expect_err("dynamic dispatch must be refused");
    let message = failure
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| failure.downcast_ref::<&str>().copied())
        .unwrap_or("");
    assert!(
        message.contains("dynamic `just` recipe name"),
        "unexpected refusal: {message}"
    );
}

#[test]
fn reachability_resolves_aliases_and_refuses_unknown_targets() {
    let aliased = parse_justfile_source(
        "alias check-proof := proof\n\nroot:\n\tjust check-proof\n\nproof:\n\techo proof\n",
    );
    let reachable = reachable_recipes(&aliased, "root");
    assert!(reachable.contains_key("proof"), "reachable: {reachable:?}");
    assert!(
        !reachable.contains_key("check-proof"),
        "aliases are canonicalized"
    );

    let unknown = parse_justfile_source("root:\n\tjust missing\n");
    let failure = std::panic::catch_unwind(|| reachable_recipes(&unknown, "root"))
        .expect_err("unknown target must be refused");
    let message = failure
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| failure.downcast_ref::<&str>().copied())
        .unwrap_or("");
    assert!(
        message.contains("`missing` must exist"),
        "unexpected refusal: {message}"
    );
}

#[test]
fn possible_branch_cannot_satisfy_required_structure() {
    let justfile = parse_justfile_source(
        "root:\n\tjust setup || just proof\n\nsetup:\n\ttrue\n\nproof:\n\techo proof\n",
    );
    assert!(reachable_recipes(&justfile, "root").contains_key("proof"));
    assert!(
        !structurally_required_recipes(&justfile, "root").contains_key("proof"),
        "a fallback that is skipped when setup succeeds is not required structure"
    );
}

#[test]
fn conditional_body_cannot_satisfy_required_structure() {
    let justfile = parse_justfile_source(
        "root:\n\t#!/usr/bin/env bash\n\tif false; then\n\t    just proof\n\tfi\n\nproof:\n\techo proof\n",
    );
    assert!(reachable_recipes(&justfile, "root").contains_key("proof"));
    assert!(!structurally_required_recipes(&justfile, "root").contains_key("proof"));
}

#[test]
fn command_arguments_named_just_do_not_count_as_calls() {
    let justfile = parse_justfile_source(
        "root:\n\techo just proof\n\tprintf '%s %s' just proof\n\nproof:\n\techo proof\n",
    );
    assert!(!reachable_recipes(&justfile, "root").contains_key("proof"));
}

#[test]
fn compound_shell_cannot_satisfy_required_structure() {
    for command in ["false && just proof || true", "exit 0; just proof"] {
        let justfile = parse_justfile_source(&format!(
            "root:\n\t#!/usr/bin/env bash\n\t{command}\n\nproof:\n\techo proof\n"
        ));
        assert!(reachable_recipes(&justfile, "root").contains_key("proof"));
        assert!(
            !structurally_required_recipes(&justfile, "root").contains_key("proof"),
            "compound line `{command}` can return success without executing proof"
        );
    }
}

#[test]
fn inline_conditional_call_remains_possible_for_exclusion() {
    let justfile = parse_justfile_source(
        "root:\n\t#!/usr/bin/env bash\n\tif true; then just proof; fi\n\nproof:\n\techo proof\n",
    );
    assert!(
        reachable_recipes(&justfile, "root").contains_key("proof"),
        "conditional calls cannot prove inclusion, but exclusions must still see them"
    );
    assert!(!structurally_required_recipes(&justfile, "root").contains_key("proof"));
}

#[test]
fn literal_env_and_command_wrappers_remain_visible() {
    let justfile = parse_justfile_source(
        "root:\n\tenv -u OLD MODE=test just first\n\tcommand -- just second\n\tcommand -v just proof\n\nfirst:\n\ttrue\n\nsecond:\n\ttrue\n\nproof:\n\ttrue\n",
    );
    let reachable = reachable_recipes(&justfile, "root");
    assert!(reachable.contains_key("first"), "reachable: {reachable:?}");
    assert!(reachable.contains_key("second"), "reachable: {reachable:?}");
    assert!(
        !reachable.contains_key("proof"),
        "`command -v` only inspects a name; reachable: {reachable:?}"
    );
}

#[test]
fn nested_shell_evaluation_containing_just_is_refused() {
    let justfile =
        parse_justfile_source("root:\n\tvalue=\"$(just proof)\"\n\nproof:\n\techo proof\n");
    let failure = std::panic::catch_unwind(|| reachable_recipes(&justfile, "root"))
        .expect_err("nested shell evaluation must be refused");
    let message = failure
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| failure.downcast_ref::<&str>().copied())
        .unwrap_or("");
    assert!(
        message.contains("nested shell evaluation containing `just`"),
        "unexpected refusal: {message}"
    );
}

#[test]
fn one_just_process_can_name_multiple_recipes() {
    let justfile =
        parse_justfile_source("root:\n\tjust safe proof\n\nsafe:\n\ttrue\n\nproof:\n\ttrue\n");
    let reachable = reachable_recipes(&justfile, "root");
    assert!(reachable.contains_key("safe"), "reachable: {reachable:?}");
    assert!(reachable.contains_key("proof"), "reachable: {reachable:?}");
    assert!(
        !structurally_required_recipes(&justfile, "root").contains_key("proof"),
        "only the primary standalone target belongs to the narrow structural set"
    );
}

#[test]
fn just_line_prefixes_do_not_hide_executed_calls() {
    let justfile = parse_justfile_source("root:\n\t-just proof\n\nproof:\n\ttrue\n");
    assert!(reachable_recipes(&justfile, "root").contains_key("proof"));
}

/// The containment proofs the required `gate-containment` lane must keep reaching.
/// Deleting one, or quietly dropping it from the lane, fails a test rather than
/// shrinking what "containment is green" means.
const CONTAINMENT_PROOFS: &[&str] = &[
    // Every no-spend rootless-OCI live binary, the OCI adversarial column and the
    // kata-floor seccomp corpus.
    "oci-live-smoke",
    // The lane's product-path step runs every smoke that spends no model budget. The
    // proof is that WIDER recipe, not `smoke` with a narrow filter, so naming `smoke`
    // here would let the lane fall back to a narrow step and stay green.
    "smoke-no-budget",
    // `recovery-checkpoint-live` is not here: its three cells are real-timer cells, so
    // it is an L2 proof — `NIGHTLY_PROOFS` holds it, and `NIGHTLY_CELLS` names its
    // host-free twins.
    "recovery-disk-full-live",
    "recovery-publication-fault-live",
    "repository-barrier-live",
];

const CHECKPOINT_LIVE_TEST: &str = "cli::recovery_capture::checkpoint_live_tests::checkpoint_source_loss_resumes_real_timer_and_successor_once_across_two_main_processes";
const CANDIDATE_RECOVERY_LIVE_TEST: &str = "cli::recovery_capture::checkpoint_live_tests::checkpoint_preserves_previously_validated_candidate_revalidates_and_lands_after_source_loss";
const CANDIDATE_CHANGED_LIVE_TEST: &str = "cli::recovery_capture::checkpoint_live_tests::checkpoint_refuses_native_landing_when_restored_candidate_changes_after_revalidation";
const DISK_FULL_RECOVERY_LIVE_TEST: &str = "cli::recovery_capture::disk_full_tests::recovery_capture_real_enospc_refuses_unpublished_artifacts";

/// Pin this one literal recipe command; this is not a general shell evaluator.
fn checkpoint_live_command_is_exact(body: &str) -> bool {
    recovery_live_command_is_exact(
        body,
        &[
            CHECKPOINT_LIVE_TEST,
            CANDIDATE_RECOVERY_LIVE_TEST,
            CANDIDATE_CHANGED_LIVE_TEST,
        ],
    )
}

fn recovery_live_command_is_exact(body: &str, tests: &[&str]) -> bool {
    let folded = body.replace("\\\n", " ");
    let commands: Vec<_> = folded
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#') && line.contains("cargo nextest run"))
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect();
    let expression = tests
        .iter()
        .map(|test| format!("test(={test})"))
        .collect::<Vec<_>>()
        .join(" | ");
    commands
        == [format!(
            "KATA_LIVE_SMOKE=1 KATA_SANDBOX_REQUIRE_LIVE=1 cargo nextest run --workspace -P live-smoke --test-threads=1 --run-ignored all -E 'package(kata) & kind(lib) & ({expression})'"
        )]
}

#[test]
fn checkpoint_source_loss_acceptance_has_an_exact_ignored_containment_route() {
    let justfile = justfile_text();
    let body =
        body_with_calls(&justfile, "recovery-checkpoint-live").expect("checkpoint recipe exists");
    assert!(
        checkpoint_live_command_is_exact(&body),
        "checkpoint recipe lost its exact ignored, serial live-smoke invocation: {body}"
    );
    assert!(body.contains("exec scripts/installed-main-lock.sh just recovery-checkpoint-live"));
    let source = std::fs::read_to_string(
        repo_root().join("bin/kata/src/cli/recovery_capture/checkpoint_live_tests.rs"),
    )
    .expect("checkpoint acceptance source exists");
    for test in [
        CHECKPOINT_LIVE_TEST,
        CANDIDATE_RECOVERY_LIVE_TEST,
        CANDIDATE_CHANGED_LIVE_TEST,
    ] {
        let name = test.rsplit("::").next().unwrap();
        assert!(
            ignored_test_names(&source).iter().any(|test| test == name),
            "contained recovery acceptance {name} must be ignored by the ordinary gate"
        );
    }
    for mutation in [
        body.replace("--run-ignored all", ""),
        body.replace("--test-threads=1", "--test-threads=2"),
        body.replace("-P live-smoke", "-P default"),
        body.replace("package(kata) & kind(lib) & ", ""),
        body.replace("kind(lib)", "kind(bin)"),
        body.replace(CHECKPOINT_LIVE_TEST, "unrelated_test"),
        body.replace(CANDIDATE_RECOVERY_LIVE_TEST, "unrelated_test"),
        body.replace(CANDIDATE_CHANGED_LIVE_TEST, "unrelated_test"),
        body.replace("KATA_SANDBOX_REQUIRE_LIVE=1", "KATA_SANDBOX_REQUIRE_LIVE=0"),
        format!("{body}\ntrue # cargo nextest run"),
    ] {
        assert!(
            !checkpoint_live_command_is_exact(&mutation),
            "counterfeit checkpoint route was accepted: {mutation}"
        );
    }
}

#[test]
fn recovery_disk_exhaustion_has_an_exact_ignored_containment_route() {
    let justfile = justfile_text();
    let body = body_with_calls(&justfile, "recovery-disk-full-live").unwrap();
    assert!(recovery_live_command_is_exact(
        &body,
        &[DISK_FULL_RECOVERY_LIVE_TEST]
    ));
    assert!(body.contains("exec scripts/installed-main-lock.sh just recovery-disk-full-live"));
    let source = std::fs::read_to_string(
        repo_root().join("bin/kata/src/cli/recovery_capture/disk_full_tests.rs"),
    )
    .unwrap();
    let name = DISK_FULL_RECOVERY_LIVE_TEST.rsplit("::").next().unwrap();
    assert!(ignored_test_names(&source).iter().any(|test| test == name));
    for mutation in [
        body.replace("--run-ignored all", ""),
        body.replace("--test-threads=1", "--test-threads=2"),
        body.replace("-P live-smoke", "-P default"),
        body.replace("package(kata) & kind(lib) & ", ""),
        body.replace("kind(lib)", "kind(bin)"),
        body.replace(DISK_FULL_RECOVERY_LIVE_TEST, "unrelated_test"),
        body.replace("KATA_SANDBOX_REQUIRE_LIVE=1", "KATA_SANDBOX_REQUIRE_LIVE=0"),
    ] {
        assert!(!recovery_live_command_is_exact(
            &mutation,
            &[DISK_FULL_RECOVERY_LIVE_TEST]
        ));
    }
}

#[test]
fn publication_sync_faults_have_an_exact_ignored_containment_route() {
    let justfile = justfile_text();
    let body = recipe_body(&justfile, "recovery-publication-fault-live")
        .expect("publication fault recipe exists");
    let expected = "env -u KATA_TEST_PUBLICATION_FAULT_MODE -u KATA_TEST_PUBLICATION_FAULT_ROOT cargo nextest run --workspace --test-threads=1 --run-ignored ignored-only -E 'package(kata-core) & kind(test) & binary(backup_durability_tests) & test(=publication_fault_experiment::publication_sync_faults_and_process_death_are_observed_at_the_syscall_boundary)' --success-output immediate";
    let exact = |candidate: &str| {
        candidate
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect::<Vec<_>>()
            == [expected]
    };
    assert!(exact(&body), "publication fault route changed: {body}");
    for mutation in [
        body.replace("-u KATA_TEST_PUBLICATION_FAULT_MODE ", ""),
        body.replace("-u KATA_TEST_PUBLICATION_FAULT_ROOT ", ""),
        body.replace("--run-ignored ignored-only", ""),
        body.replace("--test-threads=1", "--test-threads=2"),
        body.replace("package(kata-core)", "package(kata)"),
        body.replace("package(kata-core) & kind(test) & ", ""),
        body.replace("binary(backup_durability_tests)", "binary(unrelated)"),
        body.replace(
            "publication_sync_faults_and_process_death_are_observed_at_the_syscall_boundary",
            "unrelated",
        ),
        format!("{body}\ntrue"),
    ] {
        assert!(
            !exact(&mutation),
            "counterfeit fault route accepted: {mutation}"
        );
    }
}

#[test]
fn the_repository_barrier_has_an_exact_ignored_containment_route() {
    let justfile = justfile_text();
    let body = recipe_body(&justfile, "repository-barrier-live")
        .expect("the repository barrier recipe exists");
    let expected = "cargo nextest run --workspace --test-threads=1 --run-ignored ignored-only -E 'package(kata-vcs) & kind(test) & binary(repository_durability) & test(=barrier_syscalls::the_barrier_orders_writes_before_answers_at_the_syscall_boundary)' --success-output immediate";
    let exact = |candidate: &str| {
        candidate
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect::<Vec<_>>()
            == [expected]
    };
    assert!(exact(&body), "repository barrier route changed: {body}");
    for mutation in [
        body.replace("--run-ignored ignored-only", ""),
        body.replace("--test-threads=1", "--test-threads=2"),
        body.replace("package(kata-vcs)", "package(kata)"),
        body.replace("binary(repository_durability)", "binary(unrelated)"),
        body.replace(
            "the_barrier_orders_writes_before_answers_at_the_syscall_boundary",
            "unrelated",
        ),
        format!("{body}\ntrue"),
    ] {
        assert!(
            !exact(&mutation),
            "counterfeit barrier route accepted: {mutation}"
        );
    }
}

/// The PRODUCT-PATH proofs the required `gate-containment` lane must keep reaching.
///
/// Separate from [`CONTAINMENT_PROOFS`] on purpose: those run `#[ignore]`d
/// host-capability tests and are therefore forbidden in `just gate`, which is the
/// second thing [`the_containment_lane_runs_ignored_tests_and_the_gate_still_does_not`]
/// asserts about them.
/// This one runs no ignored test and spends no model budget; what keeps it out of
/// `just gate` is that it BOOTS THE PRODUCT, and
/// [`the_gate_boots_no_config_that_needs_a_model_cli`] rests on `footprint-check`
/// being the gate's only product boot.
///
/// `product-cli-smoke` is the only exerciser of the first-run operator surface —
/// `kata init` into a repository, `kata doctor`, then the whole top-level CLI
/// against an installed main. A recipe no required lane reaches can sit RED on main
/// while both required lanes stay green, so it is pinned here.
///
/// `smoke-no-budget-factory` and the recipes it calls are here for the argument
/// this whole file exists to enforce. `smoke-no-budget`
/// selects by nextest BINARY, so it can only ever reach a `#[test]` — a justfile
/// recipe is unreachable by it. The live factory proofs are recipes, so the
/// packs they drive would be covered by nothing automatic: a change that breaks
/// a LIBRARY-DEFINED stage in them would leave `just workflows-check-all` green.
/// All spend zero model budget; all boot the product, which is why they are here
/// and not in `just gate`.
///
/// `factory-self-improve-implementation-smoke` — the one of the three that makes
/// the factory MUTATE KATA'S OWN SOURCE in an isolated candidate — places its
/// config inside the project (where `.gitignore`'s `.kata/` line keeps it out of
/// the pristine assertions): a config outside the project would make `kata init`'s
/// relative `jj_repo = ".."` adopt the temp root and materialize an EMPTY
/// candidate.
const CONTAINMENT_PRODUCT_PATH_PROOFS: &[&str] = &[
    "product-cli-smoke",
    "smoke-no-budget-factory",
    "factory-self-improve-preflight-smoke",
    "factory-self-improve-implementation-smoke",
    "product-factory-smoke",
];

/// Index of the body line whose trimmed text is exactly `needle`.
///
/// Exact-line, not `body.find(needle)`: `find("just fmt")` also matches `just fmt-fix`,
/// and an ordering assertion that can be satisfied by a different recipe is not an
/// ordering assertion.
fn line_index(body: &str, needle: &str) -> Option<usize> {
    body.lines().position(|line| line.trim() == needle)
}

/// The live eval tier rides NEITHER required tier.
///
/// The gate has two L1 tiers, `gate` (commit) and `gate-push` (push), so the eval
/// exclusion is asserted over BOTH — an eval step that moved into the push tier would
/// otherwise be unwatched. The no-`--run-ignored` guarantee
/// stays COMMIT-TIER ONLY and deliberately so: it is the guarantee that an unattended
/// per-commit run cannot widen a filter into budget-spending ignored tests, and the push
/// tier ends in `gate-containment`, which exists to run exactly those ignored tests.
#[test]
fn gate_static_recipe_graph_excludes_the_live_eval_tier() {
    let justfile = justfile_text();

    for tier in ["gate", "gate-push", "gate-nightly"] {
        let reachable = reachable_recipes(&justfile, tier);
        assert!(
            !reachable.contains_key("eval-live"),
            "the `{tier}` recipe graph must NOT reach the live eval tier; reachable recipes: {:?}",
            reachable.keys().collect::<Vec<_>>()
        );
        let reachable_bodies = reachable
            .iter()
            .map(|(name, body)| format!("{name}:\n{body}"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !reachable_bodies.contains("KATA_EVAL_LIVE"),
            "the `{tier}` recipe graph must NOT set the live-eval spend acknowledgment; \
             reachable bodies:\n{reachable_bodies}"
        );
    }

    let reachable = reachable_recipes(&justfile, "gate");
    assert!(
        reachable.contains_key("test"),
        "sanity: expected the commit tier's recipe graph to reach `just test`; reachable \
         recipes: {:?}",
        reachable.keys().collect::<Vec<_>>()
    );
    let reachable_bodies = reachable
        .iter()
        .map(|(name, body)| format!("{name}:\n{body}"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !reachable_bodies.contains("--run-ignored"),
        "the COMMIT tier's recipe graph must NOT run ignored tests; reachable \
         bodies:\n{reachable_bodies}"
    );
}

/// THE TIER PARTITION, pinned step by step.
///
/// The two tiers decide WHEN each proof runs and nothing about WHAT runs before a push.
/// That claim is a set equality over the justfile, so it is asserted as one: every L1
/// step appears in EXACTLY ONE tier, each tier contains the steps it
/// is supposed to contain, and neither tier has quietly grown the other's expensive half.
/// The lock and smoke-harness self-tests are commit-tier steps the same way. REFUSED: a
/// `gate` or `gate-hosted` body without the exact lines
/// `KATA_INSTALLED_MAIN_LOCK_HELD=1 scripts/installed-main-lock.sh --self-test` and
/// `bash scripts/smoke-harness.sh --self-test`; and, in any recipe the push tier can
/// reach, an uncommented line that contains `installed-main-lock.sh` or
/// `smoke-harness.sh` and has a whitespace-separated `--self-test` word.
///
/// COUNTERFACTUAL: move `footprint-check` back into `_gate-commit-core` and this names it
/// twice — once as a commit-tier step that must not be there, once as a duplicate. Put
/// `bash ./scripts/smoke-harness.sh --self-test` in `gate-containment` and this names
/// `gate-containment`; drop `KATA_INSTALLED_MAIN_LOCK_HELD=1` from `gate`'s lock
/// self-test and this names `gate`.
#[test]
fn the_two_tiers_partition_every_l1_step() {
    let justfile = justfile_text();

    // The commit tier: cheap, host-independent, and everything a COMMIT can break.
    // `pgrep-stale` is asserted separately below: it is PROCESS HYGIENE rather than a
    // proof, the containment lane opens and closes with its own, and paying it twice
    // costs seconds.
    let commit_steps = [
        "fmt",
        "_gate-common-preflight",
        "lint",
        "deny",
        "test-doc",
        "derive-refusal-probe",
        "test",
        "agent-accept",
        "test-conformance",
    ];
    // The push tier: the host-independent steps that dominate L1's wall clock, plus
    // containment. `test-measurement` is load-sensitive, so it is L2 (`NIGHTLY_PROOFS`),
    // where `the_nightly_tier_reaches_every_nightly_proof_and_neither_l1_tier_does`
    // holds it.
    let push_steps = ["footprint-check", "test-soak", "gate-containment"];

    let commit = structurally_required_recipes(&justfile, "gate");
    let push = structurally_required_recipes(&justfile, "gate-push");

    for step in commit_steps {
        assert!(
            commit.contains_key(step),
            "the COMMIT tier (`just gate`) no longer reaches `{step}`; reachable: {:?}",
            commit.keys().collect::<Vec<_>>()
        );
        assert!(
            !push.contains_key(step),
            "`{step}` is reachable from BOTH tiers. The tiering pays each proof once; a \
             step in both tiers is the ~13 minutes the commit tier exists to stop paying."
        );
    }
    for step in push_steps {
        assert!(
            push.contains_key(step),
            "the PUSH tier (`just gate-push`) no longer reaches `{step}` — it was required \
             before push in the single lane and it still is; reachable: {:?}",
            push.keys().collect::<Vec<_>>()
        );
        assert!(
            !commit.contains_key(step),
            "`{step}` is back in the COMMIT tier. The push tier holds it because a \
             commit cannot invalidate it cheaply: the four tree steps are 819s measured, \
             and containment needs a kernel the commit tier does not require."
        );
    }

    // The self-tests keep their commit-tier position: both are seconds, and both are
    // preconditions for the product boots the push tier performs. The lock self-test runs
    // with `KATA_INSTALLED_MAIN_LOCK_HELD=1` set, as it does under the lane lock: its
    // `unset` of that variable is what keeps cells 2 and 3 meaningful there, and a run
    // without it set cannot tell the `unset` is gone.
    let gate = recipe_body(&justfile, "gate").expect("`gate` exists");
    for recipe in ["gate", "gate-hosted"] {
        let body = recipe_body(&justfile, recipe).unwrap_or_else(|| panic!("`{recipe}` exists"));
        for selftest in [
            "KATA_INSTALLED_MAIN_LOCK_HELD=1 scripts/installed-main-lock.sh --self-test",
            "bash scripts/smoke-harness.sh --self-test",
        ] {
            assert!(
                line_index(&body, selftest).is_some(),
                "`{recipe}` must run `{selftest}` exactly so; body:\n{body}"
            );
        }
    }
    // ...and ONLY there: they test two scripts the tree fixes, and L1 is both tiers over
    // one tree. The push tier's run inside `gate-containment` (11 s per L1) was the only
    // one under a held lock; the commit tier's now carries that condition, so a push-tier
    // re-run proves nothing the commit tier did not. Possible reachability: a re-run
    // behind a branch is still paid.
    for (recipe, body) in reachable_recipes(&justfile, "gate-push") {
        for script in ["installed-main-lock.sh", "smoke-harness.sh"] {
            assert!(
                !body.lines().any(|line| {
                    let line = line.trim();
                    !line.starts_with('#')
                        && line.contains(script)
                        && line.split_whitespace().any(|word| word == "--self-test")
                }),
                "`{recipe}` (reachable from the PUSH tier) re-runs `{script} --self-test`, \
                 which the COMMIT tier already ran over the same tree; body:\n{body}"
            );
        }
    }
    // `pgrep-stale` still bookends the commit tier: once before, once after.
    assert_eq!(
        gate.lines()
            .filter(|line| line.trim() == "just pgrep-stale")
            .count(),
        2,
        "the COMMIT tier must still bookend with `just pgrep-stale`; body:\n{gate}"
    );
}

// ───────────────────────────────────────────────────────────────────────────────
// ONE BUILD PER GATE: remove duplication, keep the checks.
//
// Duplicated compilation is the gate's largest avoidable cost: a second worktree's full
// test build, `-p` lists that each force their own feature-unified test build, two
// release builds of `kata`, and recipes re-running tests `just test` has just run. The
// checks below hold the de-duplicated shape — and,
// as importantly, hold the two things the overlap must never touch: a step that
// asserts wall-clock bounds, and a step that boots the per-uid installed main.
// ───────────────────────────────────────────────────────────────────────────────

/// Recipes Just runs with `[parallel]`: every dependency starts at once.
fn is_parallel(recipe: &Recipe) -> bool {
    recipe
        .attributes
        .iter()
        .any(|attribute| attribute.as_str() == Some("parallel"))
}

/// Steps that must never overlap another step: they assert wall-clock bounds, or they
/// boot the installed main, which is a per-uid singleton (`installed-main-lock.sh`).
fn must_run_alone() -> BTreeSet<&'static str> {
    [
        "footprint-check",
        "test-soak",
        "test-measurement",
        "quiet-box-wait",
        "gate-containment",
    ]
    .into_iter()
    .chain(CONTAINMENT_PROOFS.iter().copied())
    .chain(CONTAINMENT_PRODUCT_PATH_PROOFS.iter().copied())
    .chain(NIGHTLY_PROOFS.iter().copied())
    .collect()
}

/// Every `[parallel]` recipe reachable from `root`, with the reason each offends: a
/// dependency whose POSSIBLE closure reaches a must-run-alone step, or takes the
/// installed-main lock. Possible reachability, not structural: a step that only MIGHT
/// run inside an overlap is still an overlap.
fn parallel_overlap_offenders(justfile: &Justfile, root: &str) -> (usize, Vec<String>) {
    let alone = must_run_alone();
    let mut groups = 0;
    let mut offenders = Vec::new();
    for name in reachable_recipes(justfile, root).keys() {
        let recipe = &justfile.recipes[name];
        if !is_parallel(recipe) {
            continue;
        }
        groups += 1;
        for dependency in &recipe.dependencies {
            for (reached, body) in reachable_recipes(justfile, &dependency.recipe) {
                if alone.contains(reached.as_str()) {
                    offenders.push(format!(
                        "  [parallel] {name} -> {} reaches `{reached}`",
                        dependency.recipe
                    ));
                }
                if body.contains("installed-main-lock.sh") {
                    offenders.push(format!(
                        "  [parallel] {name} -> {} reaches `{reached}`, which boots an installed main",
                        dependency.recipe
                    ));
                }
            }
        }
    }
    (groups, offenders)
}

/// The overlap the tiers now use is only between steps that cannot contend.
///
/// REFUSED: a `[parallel]` group (reachable from either tier) any of whose members can
/// reach `footprint-check`, `test-soak`, `test-measurement`, `quiet-box-wait`,
/// `gate-containment`, any containment proof, or any recipe that takes the installed-main
/// lock. NOT REFUSED, and not claimed: CPU or disk contention between the members that
/// do overlap (lint beside the test build, the doctests beside the test run) — those
/// were chosen because nothing in them asserts time.
///
/// COUNTERFACTUAL: exercised below on a synthetic justfile whose group member calls
/// `just test-soak`, and on one whose member re-execs under the installed-main lock.
#[test]
fn the_parallel_groups_overlap_only_what_cannot_contend() {
    let justfile = justfile_text();
    // `gate` still overlaps (lint beside the test build; the suite beside the
    // doctests); `gate-push` is serial again — the release self-test that shared
    // its build group is retired, so it has no `[parallel]` group to be
    // vacuous about.
    let tier = "gate";
    let (groups, offenders) = parallel_overlap_offenders(&justfile, tier);
    assert!(
        groups > 0,
        "`{tier}` reaches no `[parallel]` group, so this check is vacuous for it; if \
         the tier is serial again, drop this check"
    );
    assert!(
        offenders.is_empty(),
        "a `[parallel]` group in `{tier}` overlaps a step that must run alone:\n{}",
        offenders.join("\n")
    );

    // L2 is serial by design (every step after its builds is timing- or main-bound), so
    // it has no group to be vacuous about — but a group added to it must pass the rule.
    let (_, offenders) = parallel_overlap_offenders(&justfile, "gate-nightly");
    assert!(
        offenders.is_empty(),
        "a `[parallel]` group in `gate-nightly` overlaps a step that must run alone:\n{}",
        offenders.join("\n")
    );

    let soak = parse_justfile_source(
        "[parallel]\ngroup: a b\n\na:\n    just test-soak\n\nb:\n    echo b\n\ntest-soak:\n    echo soak\n",
    );
    let (_, offenders) = parallel_overlap_offenders(&soak, "group");
    assert!(
        offenders.iter().any(|line| line.contains("`test-soak`")),
        "a group member reaching test-soak was accepted: {offenders:?}"
    );
    let boots = parse_justfile_source(
        "[parallel]\ngroup: a\n\na:\n    exec scripts/installed-main-lock.sh true\n",
    );
    let (_, offenders) = parallel_overlap_offenders(&boots, "group");
    assert!(
        offenders
            .iter()
            .any(|line| line.contains("boots an installed main")),
        "a group member taking the installed-main lock was accepted: {offenders:?}"
    );
    let serial =
        parse_justfile_source("group: a\n\na:\n    just test-soak\n\ntest-soak:\n    echo soak\n");
    assert_eq!(
        parallel_overlap_offenders(&serial, "group"),
        (0, Vec::new())
    );
}

/// Every `cargo nextest` line reachable from `root` that would BUILD test binaries for
/// a package list other than the workspace's.
fn test_rebuild_offenders(justfile: &Justfile, root: &str) -> (usize, Vec<String>) {
    let mut checked = 0;
    let mut offenders = Vec::new();
    for (recipe, body) in reachable_recipes(justfile, root) {
        let folded = body.replace("\\\n", " ");
        for line in folded.lines().map(str::trim) {
            // A message that NAMES a nextest command is not one.
            if line.starts_with('#')
                || line.starts_with("echo ")
                || line.starts_with("printf ")
                || !(line.contains("cargo nextest run") || line.contains("cargo nextest list"))
            {
                continue;
            }
            checked += 1;
            let words: Vec<&str> = line.split_whitespace().collect();
            let scoped = words.iter().any(|word| {
                matches!(
                    *word,
                    "-p" | "--package" | "--lib" | "--bins" | "--test" | "--bin" | "--exclude"
                )
            });
            let reuses = words
                .iter()
                .any(|word| matches!(*word, "--workspace" | "--binaries-metadata"));
            if scoped || !reuses {
                offenders.push(format!("  {recipe}: {line}"));
            }
        }
    }
    (checked, offenders)
}

/// No step in either tier builds its own variant of the test binaries.
///
/// REFUSED: a reachable `cargo nextest run|list` line that names a package list or a
/// target-kind flag (`-p`, `--package`, `--lib`, `--bins`, `--bin`, `--test`,
/// `--exclude`), or that neither covers the workspace (`--workspace`) nor runs a
/// recorded build (`--binaries-metadata`). Resolver 2 unifies features per package
/// list, so each such line was a separate test build — oci-live-smoke's three `-p`
/// runs alone were 165-334 s of compiling. Selection moved into the `-E` expression
/// (`package(...)`, `kind(...)`), which changes no build.
///
/// COUNTERFACTUAL: a synthetic `cargo nextest run -p kata -E 'binary(x)'` is named.
#[test]
fn every_gate_nextest_invocation_reuses_the_workspace_test_build() {
    let justfile = justfile_text();
    for tier in ["gate", "gate-push", "gate-nightly"] {
        let (checked, offenders) = test_rebuild_offenders(&justfile, tier);
        // `gate` has exactly two (`test-build`, `test`); fewer means the scan is blind.
        assert!(
            checked >= 2,
            "`{tier}`: only {checked} nextest lines found; the scan is not reading the tier"
        );
        assert!(
            offenders.is_empty(),
            "`{tier}` builds a second variant of the test binaries:\n{}\n\nSelect with \
             `--workspace -E 'package(...) & ...'` so the run reuses `just test`'s build.",
            offenders.join("\n")
        );
    }
    for counterfeit in [
        "cargo nextest run -p kata -E 'binary(x)'",
        "cargo nextest run --workspace --lib -E 'test(x)'",
        "cargo nextest run --workspace --test-threads=1 --test x",
        "cargo nextest run -E 'binary(x)'",
    ] {
        let source = format!("r:\n    {counterfeit}\n");
        let (checked, offenders) = test_rebuild_offenders(&parse_justfile_source(&source), "r");
        assert_eq!(
            (checked, offenders.len()),
            (1, 1),
            "accepted: {counterfeit}"
        );
    }
    let (_, offenders) = test_rebuild_offenders(
        &parse_justfile_source(
            "r:\n    cargo nextest run --workspace --test-threads=1 -E 'package(kata)'\n",
        ),
        "r",
    );
    assert!(
        offenders.is_empty(),
        "`--test-threads` is not a target flag: {offenders:?}"
    );
}

/// The subcommand of every `cargo` invocation on a shell line: the first word after
/// `cargo` that is neither a `+toolchain` nor a `-`-flag, skipping the separate value of
/// the global flags that take one (`--config`, `-Z`, `--color`, `--manifest-path`, `-C`),
/// so `cargo --locked build` and `cargo +nightly -Z x nextest` are seen.
fn cargo_subcommands<'a>(words: &[&'a str]) -> Vec<&'a str> {
    const TAKES_VALUE: &[&str] = &["--config", "-Z", "--color", "--manifest-path", "-C"];
    let mut out = Vec::new();
    for (at, word) in words.iter().enumerate() {
        if *word != "cargo" {
            continue;
        }
        let mut rest = words[at + 1..].iter();
        while let Some(next) = rest.next() {
            if next.starts_with('+') {
                continue;
            }
            if next.starts_with('-') {
                if TAKES_VALUE.contains(next) {
                    rest.next();
                }
                continue;
            }
            out.push(*next);
            break;
        }
    }
    out
}

/// Every `cargo build` line reachable from `root` that builds a PACKAGE-SCOPED variant
/// for the host: one naming `-p`/`--package`, `--bin`, `--lib`, `--example`, `--test` or
/// `--exclude`, unless it builds for `--target x86_64-unknown-linux-musl` (the static
/// capsule binaries, in their own target directory, which no host build shares).
fn scoped_build_offenders(justfile: &Justfile, root: &str) -> (usize, Vec<String>) {
    let mut checked = 0;
    let mut offenders = Vec::new();
    for (recipe, body) in reachable_recipes(justfile, root) {
        for line in body.replace("\\\n", " ").lines().map(str::trim) {
            if line.starts_with('#') || line.starts_with("echo ") || line.starts_with("printf ") {
                continue;
            }
            let words: Vec<&str> = line.split_whitespace().collect();
            if !cargo_subcommands(&words).contains(&"build") {
                continue;
            }
            checked += 1;
            let musl = words
                .windows(2)
                .any(|pair| pair == ["--target", "x86_64-unknown-linux-musl"])
                || words.contains(&"--target=x86_64-unknown-linux-musl");
            let scoped = words.iter().any(|word| {
                matches!(
                    *word,
                    "-p" | "--package" | "--bin" | "--lib" | "--example" | "--test" | "--exclude"
                ) || word.starts_with("--package=")
                    || word.starts_with("--bin=")
            });
            if scoped && !musl {
                offenders.push(format!("  {recipe}: {line}"));
            }
        }
    }
    (checked, offenders)
}

/// The debug binaries the tiers boot and locate are the ONE workspace bins build.
///
/// REFUSED: a reachable `cargo build` line building a package-scoped host variant
/// ([`scoped_build_offenders`]) — resolver 2 unifies features per selected package set,
/// so `cargo build -p kata` after the workspace build recompiled 15 crates (43.72 s at
/// ba3b5c727, in `oci-live-smoke`'s preamble) and left a `target/debug/kata` linked
/// against a different feature set than the one the suite judged; a `build-debug` or
/// `oci-live-smoke` that does not reach `_workspace-bins`. NOT refused: the
/// `x86_64-unknown-linux-musl` builds of the static capsule binaries.
///
/// COUNTERFACTUAL: synthetic `cargo build -p kata`, `cargo --locked build -p kata` (a
/// global flag before the subcommand, [`cargo_subcommands`]) and `cargo build
/// --workspace --bin kata` lines are named; `cargo build --workspace --bins` and a musl
/// `-p` build are not.
#[test]
fn every_tier_builds_its_debug_binaries_with_the_workspace() {
    let justfile = justfile_text();
    for tier in ["gate", "gate-push"] {
        let (checked, offenders) = scoped_build_offenders(&justfile, tier);
        assert!(
            checked >= 1,
            "`{tier}`: no `cargo build` line found; the scan is blind"
        );
        assert!(
            offenders.is_empty(),
            "`{tier}` builds a package-scoped variant of the host binaries:\n{}\n\nBuild \
             with `just _workspace-bins` (what `build-debug` is), so every recipe boots \
             the binaries the workspace build produced.",
            offenders.join("\n")
        );
    }
    for recipe in ["build-debug", "oci-live-smoke"] {
        assert!(
            structurally_required_recipes(&justfile, recipe).contains_key("_workspace-bins"),
            "`{recipe}` no longer builds through `_workspace-bins`"
        );
    }
    for (line, named) in [
        ("cargo build -p kata", 1),
        ("cargo --locked build -p kata", 1),
        ("cargo build --workspace --bin kata", 1),
        ("cargo build --workspace --bins", 0),
        ("cargo build -p kata --target x86_64-unknown-linux-musl", 0),
    ] {
        let source = format!("r:\n    {line}\n");
        let (checked, offenders) = scoped_build_offenders(&parse_justfile_source(&source), "r");
        assert_eq!((checked, offenders.len()), (1, named), "{line}");
    }
}

/// ONE release build serves both tiers, and it is the shipped artifact's build.
///
/// REFUSED: any reachable `cargo build ... --release` line other than the single line
/// `cargo build --workspace --release` in `build`; a `footprint-check` that does not
/// reach `build`; and a `build` whose workspace shape no longer matches what the
/// flake's `cargoBuildFlags` builds the shipped artifact with. A `--release -p kata`
/// build for `footprint-check` would be a second ~155 s LTO build, of bytes that do not
/// ship.
#[test]
fn one_release_build_serves_both_tiers_and_it_is_the_shipped_one() {
    let justfile = justfile_text();
    let shipped = "cargo build --workspace --release";
    let mut release_lines = BTreeSet::new();
    for tier in ["gate", "gate-push"] {
        for (recipe, body) in reachable_recipes(&justfile, tier) {
            for line in body.replace("\\\n", " ").lines().map(str::trim) {
                if !line.starts_with('#')
                    && line.contains("cargo build")
                    && line.contains("--release")
                {
                    release_lines.insert(format!("{recipe}: {line}"));
                }
            }
        }
    }
    assert_eq!(
        release_lines,
        BTreeSet::from([format!("build: {shipped}")]),
        "the tiers must build release exactly once, through `build`"
    );
    assert!(structurally_required_recipes(&justfile, "footprint-check").contains_key("build"));
    let flake = std::fs::read_to_string(repo_root().join("flake.nix")).expect("flake.nix exists");
    assert!(
        flake.contains("cargoBuildFlags") && flake.contains("\"--workspace\""),
        "the flake's kata package no longer builds the workspace; `build` must track \
         the shipped artifact's build or footprint-check measures bytes that do not ship"
    );
}

/// Every Nix line reachable from `root` that realises or evaluates something L1 must
/// not: a `nix` command whose subcommand is `build`, `shell`, `run`, `eval`,
/// `path-info`, `develop` or `profile`, or a call of `scripts/oci-smoke-node.sh`'s
/// `oci_smoke_nix_paths`, that names the flake's own `kata` package — an installable
/// ending in `#kata` or `#default` — or, outside `oci_smoke_nix_paths` (whose own pin
/// [`nix_paths_function_pins_the_lock`] checks), names a registry `nixpkgs#…`
/// installable without `--inputs-from` (which resolves the floating channel, not
/// `flake.lock`); and every `nix-shell` or `nix-build` line, which resolve `<nixpkgs>`
/// from `NIX_PATH`, a channel no lock pins.
fn l1_nix_offenders(justfile: &Justfile, root: &str) -> Vec<String> {
    const SUBCOMMANDS: &[&str] = &[
        "build",
        "shell",
        "run",
        "eval",
        "path-info",
        "develop",
        "profile",
    ];
    const TAKES_VALUE: &[&str] = &[
        "--extra-experimental-features",
        "--experimental-features",
        "--log-format",
        "--store",
    ];
    fn unquote(word: &str) -> &str {
        word.trim_matches(|c| matches!(c, '"' | '\'' | '(' | ')'))
    }
    let names_kata = |word: &str| {
        let word = unquote(word);
        word.ends_with("#kata") || word.ends_with("#default")
    };
    let mut offenders = Vec::new();
    for (recipe, body) in reachable_recipes(justfile, root) {
        for line in body.replace("\\\n", " ").lines().map(str::trim) {
            if line.starts_with('#') || line.starts_with("echo ") || line.starts_with("printf ") {
                continue;
            }
            let words: Vec<&str> = line.split_whitespace().collect();
            if words
                .iter()
                .any(|word| matches!(unquote(word), "nix-shell" | "nix-build"))
            {
                offenders.push(format!(
                    "  {recipe}: resolves `<nixpkgs>` from NIX_PATH: {line}"
                ));
                continue;
            }
            let through_function = line.contains("oci_smoke_nix_paths");
            let nix_command = words.iter().enumerate().any(|(at, word)| {
                unquote(word) == "nix" && {
                    // The subcommand: the first word that is not a flag or a flag's value.
                    let mut rest = words[at + 1..].iter();
                    let sub = loop {
                        match rest.next() {
                            Some(&"--option") => {
                                rest.nth(1);
                            }
                            Some(flag) if TAKES_VALUE.contains(flag) => {
                                rest.next();
                            }
                            Some(flag) if flag.starts_with('-') => {}
                            other => break other,
                        }
                    };
                    sub.is_some_and(|sub| SUBCOMMANDS.contains(sub))
                }
            });
            if !(nix_command || through_function) {
                continue;
            }
            if words.iter().any(|word| names_kata(word)) {
                offenders.push(format!(
                    "  {recipe}: realises the flake's kata package: {line}"
                ));
            }
            if !through_function
                && !line.contains("--inputs-from")
                && words
                    .iter()
                    .any(|word| unquote(word).starts_with("nixpkgs#"))
            {
                offenders.push(format!(
                    "  {recipe}: resolves the unpinned registry: {line}"
                ));
            }
        }
    }
    offenders
}

/// Does the sourced helper's `oci_smoke_nix_paths` resolve `nixpkgs#…` against the
/// repository's `flake.lock` (`--inputs-from` the checkout) rather than the registry?
fn nix_paths_function_pins_the_lock(script: &str) -> bool {
    let Some(start) = script.find("oci_smoke_nix_paths() {") else {
        return false;
    };
    let body = &script[start..];
    let body = &body[..body.find("\n}").unwrap_or(body.len())];
    body.lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .any(|line| line.contains("nix build") && line.contains("--inputs-from"))
}

/// L1 builds no Nix package of kata and resolves no floating channel.
///
/// REFUSED, from either L1 tier: a Nix realisation of the flake's own `kata` package
/// ([`l1_nix_offenders`]) — at ba3b5c727 `factory-self-improve-preflight-smoke` built
/// `.#kata` (a cold `cargo build --workspace --release` under Nix, ~210 s of every L1)
/// for the one binary its capsule execs, work verification.md assigns to L2's
/// `flake-checks`; a `nix build`/`shell`/`run`/`eval`/`path-info`/`develop`/`profile`
/// of a `nixpkgs#…` installable without `--inputs-from`; any `nix-shell` or `nix-build`;
/// and an `oci_smoke_nix_paths` whose `nix build` does not pass `--inputs-from` (the same
/// smoke unpacked the `nixpkgs-unstable` channel tarball on every gate, so a verdict
/// could move with the channel). NOT refused: L2's `flake-checks`, which is the place
/// the flake package is built; substitution from a binary cache of a locked path.
///
/// COUNTERFACTUAL: synthetic `<(oci_smoke_nix_paths nixpkgs#just "$repo_root#kata")`,
/// `nix build nixpkgs#python3`, `nix shell nixpkgs#hello -c true`, `nix --option a b
/// --extra-experimental-features x eval nixpkgs#x` and `nix-shell -p hello` lines are named; `nix build --inputs-from .
/// nixpkgs#x`, `nix shell --inputs-from . nixpkgs#x` and `nix store add-path` are not; a
/// helper without `--inputs-from` is refused.
#[test]
fn l1_builds_no_nix_kata_and_resolves_no_floating_channel() {
    let justfile = justfile_text();
    for tier in ["gate", "gate-push"] {
        let offenders = l1_nix_offenders(&justfile, tier);
        assert!(
            offenders.is_empty(),
            "`{tier}` realises what L1 must not:\n{}\n\nThe in-capsule `kata` is the static \
             musl build (`oci_smoke_kata_tool`); the flake package is L2's `flake-checks`.",
            offenders.join("\n")
        );
    }
    let script = std::fs::read_to_string(repo_root().join("scripts/oci-smoke-node.sh"))
        .expect("scripts/oci-smoke-node.sh exists");
    assert!(
        nix_paths_function_pins_the_lock(&script),
        "`oci_smoke_nix_paths` resolves `nixpkgs#…` without `--inputs-from`, i.e. against \
         the floating registry entry instead of flake.lock"
    );

    let planted = parse_justfile_source(
        "r:\n    mapfile -t x < <(oci_smoke_nix_paths nixpkgs#just \"$repo_root#kata\")\n    nix build nixpkgs#python3\n    nix shell nixpkgs#hello -c true\n    nix --option a b --extra-experimental-features x eval nixpkgs#x\n    nix-shell -p hello\n    nix build --inputs-from . nixpkgs#x\n    nix shell --inputs-from . nixpkgs#x -c true\n    nix store add-path \"$dir\"\n",
    );
    let named = l1_nix_offenders(&planted, "r");
    assert_eq!(named.len(), 5, "{named:?}");
    assert!(!nix_paths_function_pins_the_lock(
        "oci_smoke_nix_paths() {\n    nix build --no-link \"$@\"\n}\n"
    ));
    assert!(nix_paths_function_pins_the_lock(
        "oci_smoke_nix_paths() {\n    nix build --no-link --inputs-from \"$root\" \"$@\"\n}\n"
    ));
}

/// `agent-accept`, `test-conformance` and `youki-pin-cells-ran` read `just test`'s report;
/// they do not re-run it.
///
/// REFUSED: any of them running `cargo nextest run` again; any of them not going
/// through scripts/check-junit-ran.py (whose own self-test, run by `dev-loop-check`,
/// proves its refusals: absent, failed, errored, skipped, wrong binary, empty); a commit
/// tier that reads the report before the run group, or that does not delete the stale
/// report before `test` writes a fresh one; and a nextest config without the default
/// profile's JUnit output the check reads.
#[test]
fn acceptance_and_conformance_check_the_suite_report_instead_of_rerunning_it() {
    let justfile = justfile_text();
    for recipe in ["agent-accept", "test-conformance", "youki-pin-cells-ran"] {
        let body = recipe_body(&justfile, recipe).unwrap_or_else(|| panic!("`{recipe}` exists"));
        assert!(
            !body.contains("cargo nextest run"),
            "`{recipe}` re-runs tests:\n{body}"
        );
        assert!(
            body.contains("python3 -B scripts/check-junit-ran.py -E "),
            "`{recipe}` no longer checks the suite report:\n{body}"
        );
    }
    let core = recipe_body(&justfile, "_gate-commit-core").expect("commit core exists");
    let at = |needle: &str| {
        line_index(&core, needle)
            .unwrap_or_else(|| panic!("`_gate-commit-core` lost `{needle}`:\n{core}"))
    };
    let delete = at("rm -f target/nextest/default/junit.xml");
    let run = at("just _gate-commit-run");
    assert!(
        delete < run,
        "the stale report must be deleted before `test` runs"
    );
    assert!(
        run < at("just agent-accept")
            && run < at("just test-conformance")
            && run < at("just youki-pin-cells-ran")
    );
    assert!(
        structurally_required_recipes(&justfile, "_gate-commit-run").contains_key("test"),
        "the run group no longer runs `test`, so the report the checks read is not the suite's"
    );
    let nextest =
        std::fs::read_to_string(repo_root().join(".config/nextest.toml")).expect("nextest config");
    assert!(
        nextest
            .lines()
            .any(|line| line.trim() == "[profile.default.junit]"),
        "the default profile no longer writes the JUnit report agent-accept and test-conformance read"
    );
}

/// Every tier ends on a source tree its run did not change, and the commit tier checks
/// once more right after the suite.
///
/// REFUSED: a tier root (`gate`, `gate-push`, `gate-hosted`) that does not take the
/// baseline before its first step, or does not reach `source-tree-unchanged` AFTER its
/// last expensive step; a commit core that does not check right after the run group.
#[test]
fn every_tier_ends_on_an_unchanged_source_tree() {
    let justfile = justfile_text();
    for (tier, last_step) in [
        ("gate", "just _gate-commit-core"),
        ("gate-push", "just gate-containment"),
        ("gate-hosted", "just _gate-push-core"),
        ("gate-nightly", "just flake-checks"),
    ] {
        let body = recipe_body(&justfile, tier).unwrap_or_else(|| panic!("`{tier}` exists"));
        let baseline = line_index(&body, "source scripts/gate-source-tree.sh")
            .unwrap_or_else(|| panic!("`{tier}` takes no source-tree baseline:\n{body}"));
        let first_step = body
            .lines()
            .position(|line| line.trim().starts_with("just "))
            .expect("a tier runs steps");
        assert!(
            baseline < first_step,
            "`{tier}` baselines after a step has run"
        );
        let lines: Vec<&str> = body.lines().collect();
        let check = lines
            .iter()
            .rposition(|line| line.trim() == "just source-tree-unchanged")
            .unwrap_or_else(|| panic!("`{tier}` never checks the source tree:\n{body}"));
        assert!(check > line_index(&body, last_step).expect("the tier's last step"));
        assert!(
            structurally_required_recipes(&justfile, tier).contains_key("source-tree-unchanged")
        );
    }
    let core = recipe_body(&justfile, "_gate-commit-core").unwrap();
    assert!(
        line_index(&core, "just _gate-commit-run").unwrap()
            < line_index(&core, "just source-tree-unchanged").expect("checked after the suite")
    );
}

/// The push tier learns what the HOST cannot do before it builds anything, and waits
/// for a quiet box before its timing-sensitive steps.
///
/// REFUSED: `gate-push` running `_gate-push-core` before `pgrep-stale` and
/// `_containment-preconditions`; `quiet-box-wait` missing from before `footprint-check`
/// in the push core or from before `gate-containment` in the push tier.
#[test]
fn the_push_tier_checks_the_host_first_and_times_on_a_quiet_box() {
    let justfile = justfile_text();
    let push = recipe_body(&justfile, "gate-push").unwrap();
    let core_at = line_index(&push, "just _gate-push-core").unwrap();
    for host in ["just pgrep-stale", "just _containment-preconditions"] {
        assert!(
            line_index(&push, host).unwrap_or_else(|| panic!("`gate-push` lost `{host}`"))
                < core_at,
            "`gate-push` builds before `{host}`"
        );
    }
    assert!(
        line_index(&push, "just quiet-box-wait").expect("gate-push waits for a quiet box")
            < line_index(&push, "just gate-containment").unwrap()
    );
    let core = recipe_body(&justfile, "_gate-push-core").unwrap();
    assert!(
        line_index(&core, "just quiet-box-wait").expect("the push core waits for a quiet box")
            < line_index(&core, "just footprint-check").unwrap()
    );
}

#[test]
fn eval_recipes_exist_and_only_eval_live_spends() {
    let justfile = justfile_text();

    let eval = recipe_body(&justfile, "eval").expect("a deterministic `eval` recipe exists");
    let eval_live =
        recipe_body(&justfile, "eval-live").expect("a hand-run `eval-live` recipe exists");

    // The deterministic tier is model-free: it neither acknowledges spend nor
    // runs the live golden corpus.
    assert!(
        !eval.contains("KATA_EVAL_LIVE"),
        "the deterministic `eval` recipe must not touch the live spend flag; body:\n{eval}"
    );

    // The live tier carries the explicit spend acknowledgment — the machine
    // marker that only THIS recipe can spend model budget.
    assert!(
        eval_live.contains("KATA_EVAL_LIVE"),
        "the `eval-live` recipe must set the KATA_EVAL_LIVE spend acknowledgment; body:\n{eval_live}"
    );

    // And `eval` runs the deterministic kata-eval tier.
    assert!(
        eval.contains("kata-eval") || eval.contains("fixture_corpus"),
        "the `eval` recipe should run the deterministic eval tier; body:\n{eval}"
    );
}

/// `eval-live` `source`s `scripts/smoke-harness.sh` and arms `trap cleanup EXIT`
/// under `set -euo pipefail`. Two hazards break teardown through that EXIT trap,
/// and neither is catchable by `bash -n`:
///   (1) the SOURCED cleanup() runs `capture_evidence` first — if that is
///       undefined the trap dies with 127 BEFORE terminate_solo + `rm -rf "$tmp"`
///       ever run (every run reports FAILED, the temp dir leaks, a booted
///       installed main is orphaned); and
///   (2) the shared `terminate_solo` returns non-zero once the node is dead (its
///       `solo_alive || return` artifact), so under `set -e` the sourced cleanup
///       aborts BEFORE `rm -rf "$tmp"` on a *failure* exit and leaks the temp dir.
///
/// eval-live closes both by OWNING a self-contained cleanup that guards
/// terminate_solo (`terminate_solo || true`) so `rm -rf "$tmp"` runs on every exit
/// path. This static check pins that safe shape (or, if a future maintainer
/// reverts to the sourced cleanup, requires `capture_evidence` before the trap).
#[test]
fn eval_live_exit_trap_tears_down_cleanly() {
    let justfile = justfile_text();
    let body = recipe_body(&justfile, "eval-live").expect("an `eval-live` recipe exists");

    assert!(
        body.contains("source scripts/smoke-harness.sh"),
        "eval-live is expected to source the shared smoke harness; body:\n{body}"
    );
    let trap_idx = body
        .find("trap cleanup EXIT")
        .expect("eval-live arms the shared EXIT-trap cleanup; body:\n{body}");

    if let Some(def_idx) = body.find("cleanup() {").or_else(|| body.find("cleanup(){")) {
        // Self-contained cleanup (the chosen fix): must be defined before the trap
        // is armed, must both terminate the node and remove the temp dir, and must
        // guard terminate_solo so `set -e` cannot abort before the removal on a
        // failure exit.
        assert!(
            def_idx < trap_idx,
            "eval-live cleanup() must be defined before `trap cleanup EXIT`; body:\n{body}"
        );
        let own = &body[def_idx..];
        assert!(
            own.contains("terminate_solo"),
            "eval-live cleanup must terminate the installed main; body:\n{body}"
        );
        assert!(
            own.contains("remove_scratch \"$tmp\""),
            "eval-live cleanup must remove the temp dir through `remove_scratch`, which \
             also removes the sealed provider store; body:\n{body}"
        );
        assert!(
            own.contains("terminate_solo ||"),
            "eval-live cleanup must guard terminate_solo (e.g. `terminate_solo || true`) \
             so `remove_scratch \"$tmp\"` still runs on a failure exit — terminate_solo returns \
             non-zero once the node is dead; body:\n{body}"
        );
    } else {
        // Fallback: relies on the SOURCED cleanup(), which runs capture_evidence
        // first — that MUST be defined before the trap or the EXIT trap dies with
        // 127 before any teardown.
        let ce_idx = body.find("capture_evidence()").unwrap_or_else(|| {
            panic!(
                "eval-live uses the sourced cleanup() (which calls capture_evidence) \
                 but never defines capture_evidence — the EXIT trap will die with 127 \
                 before terminate_solo/rm run; body:\n{body}"
            )
        });
        assert!(
            ce_idx < trap_idx,
            "capture_evidence must be defined BEFORE `trap cleanup EXIT` is armed; body:\n{body}"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────────
// The gate's FEEDBACK LOOP and its CONTAINMENT BLIND SPOT.
//
// This file is the only machine check on the justfile, so both properties below are
// asserted here or nowhere. They are two halves of one finding: `just gate` was slow to
// tell you about a trivial mistake, and silent about a serious one.
// ───────────────────────────────────────────────────────────────────────────────

/// `fmt` must run before anything that compiles, in every gate variant.
///
/// THE DEFECT THIS PINS. `fmt` was the first line of `_gate-post-release-mode-core`,
/// which ran AFTER an expensive self-test and paid a full workspace compile before
/// it. One session lost four gate runs and none of them died on a defect; one died
/// on a `fmt` diff over a single wrapped `let` chain, roughly twenty minutes in.
/// `fmt` costs seconds — rustfmt parses, it does not build — has the highest
/// observed failure rate of any step, and is the only failing step with a
/// one-command fix.
///
/// COUNTERFACTUAL: move `just fmt` back into either core recipe and this fails on both
/// halves — the ordering assertion and the "not in a core" assertion.
///
/// `fmt` is checked against BOTH cores, `_gate-commit-core` and `_gate-push-core`.
/// `gate-push` is absent from the list on purpose: it runs only after a green commit tier,
/// which is where `fmt` lives, so requiring `fmt` there would pay rustfmt twice.
#[test]
fn fmt_runs_before_the_gate_compiles_anything() {
    let justfile = justfile_text();

    for (gate, expensive_steps) in [
        ("gate", vec!["just _gate-commit-core"]),
        (
            "gate-hosted",
            vec!["just _gate-commit-core", "just _gate-push-core"],
        ),
    ] {
        let body = recipe_body(&justfile, gate).unwrap_or_else(|| panic!("`{gate}` exists"));
        let fmt = line_index(&body, "just fmt")
            .unwrap_or_else(|| panic!("`{gate}` must run `just fmt` directly; body:\n{body}"));
        for expensive in expensive_steps {
            let at = line_index(&body, expensive).unwrap_or_else(|| {
                panic!("`{gate}` is expected to run `{expensive}`; body:\n{body}")
            });
            assert!(
                fmt < at,
                "`{gate}` runs `{expensive}` (line {at}) before `just fmt` (line {fmt}). \
                 fmt is seconds and fails most often; putting it behind a compile costs \
                 ~20 minutes per formatting mistake. Body:\n{body}"
            );
        }
    }

    for core in ["_gate-commit-core", "_gate-push-core"] {
        let body = recipe_body(&justfile, core).unwrap_or_else(|| panic!("`{core}` exists"));
        assert!(
            line_index(&body, "just fmt").is_none(),
            "`just fmt` is back inside `{core}`, which runs behind a compile — that is the \
             position this test exists to forbid. Body:\n{body}"
        );
    }
}

/// `recipe`'s body with each line that is exactly `just NAME`, unindented, replaced by
/// NAME's body: what the recipe runs, in order, where a gate recipe's runs stand in
/// recipes of their own ([`read_gates`]) that it calls. One level deep; an indented
/// call (inside a conditional) and a call with arguments are left as written.
fn body_with_calls(justfile: &Justfile, recipe: &str) -> Option<String> {
    let body = recipe_body(justfile, recipe)?;
    Some(
        body.lines()
            .map(|line| {
                line.strip_prefix("just ")
                    .filter(|callee| justfile.recipes.contains_key(*callee))
                    .and_then(|callee| recipe_body(justfile, callee))
                    .unwrap_or_else(|| format!("{line}\n"))
            })
            .collect(),
    )
}

/// The recipes that run the suite on the test tmpfs (verification.md, "Test TMPDIR").
const TEST_TMPFS_RECIPES: [&str; 5] = [
    "test",
    "test-crate",
    "test-one-crate",
    "test-one",
    "youki-pin-cells",
];

/// Why `recipe` does not run its suite on the test tmpfs, or `None` when it does: it
/// must be a shebang recipe (a line recipe runs each line in its own shell, so a
/// `source` there exports nothing to the next line) whose body has the exact top-level
/// line `source scripts/test-tmpfs.sh` before its first `cargo nextest run`, and at
/// least one such run. A `source` inside a conditional, loop or function runs only
/// possibly, and a compound line (`source … || true`) is not the exact line. The body is
/// read with its calls ([`body_with_calls`]): a run in a recipe it calls by `just NAME`
/// inherits the TMPDIR it exported.
fn test_tmpfs_offence(justfile: &Justfile, recipe: &str) -> Option<String> {
    let Some(body) = body_with_calls(justfile, recipe) else {
        return Some(format!("`{recipe}` does not exist"));
    };
    if !body
        .lines()
        .next()
        .is_some_and(|line| line.trim_start().starts_with("#!"))
    {
        return Some(format!("`{recipe}` is not a shebang recipe; body:\n{body}"));
    }
    let lines = logical_lines(&body, recipe);
    let source = lines.iter().position(|line| {
        !line.inside_control && line.text.trim() == "source scripts/test-tmpfs.sh"
    });
    let first_nextest = lines
        .iter()
        .position(|line| line.text.trim_start().starts_with("cargo nextest run"));
    match (source, first_nextest) {
        (_, None) => Some(format!(
            "`{recipe}` runs no `cargo nextest run`; body:\n{body}"
        )),
        (None, Some(_)) => Some(format!(
            "`{recipe}` has no top-level `source scripts/test-tmpfs.sh` line; body:\n{body}"
        )),
        (Some(source), Some(nextest)) if source > nextest => Some(format!(
            "`{recipe}` runs `cargo nextest run` before it sources the test tmpfs; body:\n{body}"
        )),
        _ => None,
    }
}

/// The suite's tempdirs stay on the test tmpfs: every recipe L0 and the commit tier run
/// the suite through sources `scripts/test-tmpfs.sh` before nextest. Without the line the
/// run silently inherits a disk-backed TMPDIR and every guard but this one stays green.
#[test]
fn the_suite_recipes_source_the_test_tmpfs_before_nextest() {
    let justfile = justfile_text();
    let offences: Vec<String> = TEST_TMPFS_RECIPES
        .iter()
        .filter_map(|recipe| test_tmpfs_offence(&justfile, recipe))
        .collect();
    assert!(
        offences.is_empty(),
        "a suite recipe would run on the inherited TMPDIR (verification.md, \"Test \
         TMPDIR\"):\n{}",
        offences.join("\n\n")
    );
}

#[test]
fn the_test_tmpfs_rule_refuses_each_shape_that_skips_the_tmpfs() {
    let shebang = "#!/usr/bin/env bash\n\tset -euo pipefail";
    for (shape, body) in [
        (
            "missing",
            format!("{shebang}\n\tcargo nextest run --workspace"),
        ),
        (
            "line recipe",
            "source scripts/test-tmpfs.sh\n\tcargo nextest run --workspace".to_owned(),
        ),
        (
            "after nextest",
            format!("{shebang}\n\tcargo nextest run --workspace\n\tsource scripts/test-tmpfs.sh"),
        ),
        (
            "conditional",
            format!(
                "{shebang}\n\tif [ -n \"${{CI:-}}\" ]; then\n\t    source scripts/test-tmpfs.sh\n\tfi\n\tcargo nextest run --workspace"
            ),
        ),
        (
            "compound",
            format!(
                "{shebang}\n\tsource scripts/test-tmpfs.sh || true\n\tcargo nextest run --workspace"
            ),
        ),
        (
            "no nextest",
            format!("{shebang}\n\tsource scripts/test-tmpfs.sh"),
        ),
    ] {
        let justfile = parse_justfile_source(&format!("test:\n\t{body}\n"));
        assert!(
            test_tmpfs_offence(&justfile, "test").is_some(),
            "the `{shape}` shape was accepted:\n{body}"
        );
    }
    let justfile = parse_justfile_source(&format!(
        "test:\n\t{shebang}\n\tsource scripts/test-tmpfs.sh\n\tcargo nextest run --workspace\n"
    ));
    assert_eq!(test_tmpfs_offence(&justfile, "test"), None);
}

/// The `cargo` command lines reachable from `root` that COMPILE: `build`, `check`,
/// `clippy`, `nextest`, `test`, `run`, `rustc` or `doc`, behind any `+toolchain` and
/// global flags ([`cargo_subcommands`]).
/// `cargo fmt` parses and builds nothing, so it is not one; a comment or an `echo` /
/// `printf` that names a command is not one either. Shell continuations are folded
/// first. This reads the recipe graph only: a script a recipe runs is not opened.
fn compile_lines(justfile: &Justfile, root: &str) -> Vec<String> {
    const COMPILING: &[&str] = &[
        "build", "check", "clippy", "nextest", "test", "run", "rustc", "doc",
    ];
    let mut out = Vec::new();
    for (recipe, body) in reachable_recipes(justfile, root) {
        for line in body.replace("\\\n", " ").lines().map(str::trim) {
            if line.starts_with('#') || line.starts_with("echo ") || line.starts_with("printf ") {
                continue;
            }
            let words: Vec<&str> = line.split_whitespace().collect();
            if cargo_subcommands(&words)
                .iter()
                .any(|sub| COMPILING.contains(sub))
            {
                out.push(format!("  {recipe}: {line}"));
            }
        }
    }
    out
}

/// The preflight every gate variant shares compiles NOTHING, and the two variants with a
/// build group run it INSIDE that group.
///
/// REFUSED: a `_gate-common-preflight` that does not reach `htree-preflight` and
/// `dev-loop-check` by unconditional calls; any compiling `cargo` line
/// ([`compile_lines`]) reachable from it — the preflight's old nextest line made the
/// commit tier pay its first workspace test build (99 s at ba3b5c727) serially ahead of
/// the `[parallel]` group, and made a docs-only `just verify` compile the workspace; `gate`
/// or `gate-hosted` calling it at top level (serially) rather than through a member of
/// the `[parallel]` `_gate-commit-build`, or calling `_gate-commit-core` before `fmt`;
/// `gate-scoped`, which has no build group, running it before `fmt`, conditionally or
/// not at all; any variant calling `dev-loop-check` beside the shared recipe. NOT
/// refused, and not claimed: a compile inside a script a preflight recipe runs.
///
/// COUNTERFACTUAL: a synthetic preflight carrying a `cargo nextest run --workspace` line
/// is named, and so are a `+toolchain` build, a `cargo --locked nextest run` and a
/// `cargo --config k=v --color never check`; `cargo +nightly fmt` and `cargo --locked
/// fmt` are not.
#[test]
fn the_preflight_compiles_nothing_and_overlaps_the_build_group() {
    let justfile = justfile_text();
    let shared = recipe_body(&justfile, "_gate-common-preflight")
        .expect("gate variants must share one explicit preflight recipe");
    let shared_required = structurally_required_recipes(&justfile, "_gate-common-preflight");
    for required in ["htree-preflight", "dev-loop-check"] {
        assert!(
            line_index(&shared, &format!("just {required}")).is_some()
                && shared_required.contains_key(required),
            "the shared preflight no longer runs `{required}` unconditionally:\n{shared}"
        );
    }
    let compiles = compile_lines(&justfile, "_gate-common-preflight");
    assert!(
        compiles.is_empty(),
        "the shared preflight compiles, so every commit tier pays that build serially \
         ahead of its build group and every docs-only `just verify` pays it at all:\n{}",
        compiles.join("\n")
    );

    let build = &justfile.recipes["_gate-commit-build"];
    assert!(
        is_parallel(build),
        "`_gate-commit-build` is no longer `[parallel]`"
    );
    assert!(
        build.dependencies.iter().any(|member| {
            structurally_required_recipes(&justfile, &member.recipe)
                .contains_key("_gate-common-preflight")
        }),
        "no member of the `[parallel]` `_gate-commit-build` runs the shared preflight"
    );
    for gate in ["gate", "gate-hosted"] {
        let body = recipe_body(&justfile, gate).unwrap_or_else(|| panic!("`{gate}` exists"));
        assert!(
            line_index(&body, "just _gate-common-preflight").is_none(),
            "`{gate}` runs the shared preflight serially, ahead of the build group it \
             belongs in; body:\n{body}"
        );
        let format = line_index(&body, "just fmt").expect("format check");
        let core = line_index(&body, "just _gate-commit-core").expect("the commit core");
        assert!(format < core, "{gate} must fail fast on formatting");
        assert!(
            structurally_required_recipes(&justfile, gate).contains_key("_gate-common-preflight"),
            "`{gate}` no longer reaches the shared preflight"
        );
        assert!(
            !body.contains("just dev-loop-check"),
            "{gate} duplicates the shared routing guard"
        );
    }
    let scoped = recipe_body(&justfile, "gate-scoped").expect("`gate-scoped` exists");
    let format = line_index(&scoped, "just fmt").expect("format check");
    let preflight =
        line_index(&scoped, "just _gate-common-preflight").expect("gate-scoped runs the preflight");
    assert!(
        format < preflight,
        "gate-scoped must fail fast on formatting"
    );
    assert!(
        structurally_required_recipes(&justfile, "gate-scoped")
            .contains_key("_gate-common-preflight")
    );
    assert!(!scoped.contains("just dev-loop-check"));

    let planted = parse_justfile_source(
        "p:\n    python3 x.py\n    cargo nextest run --workspace -E 'test(x)'\n    cargo +nightly build\n    cargo --locked nextest run --workspace -E 'test(x)'\n    cargo --config k=v --color never check\n    cargo +nightly fmt -- --check\n    cargo --locked fmt -- --check\n    echo 'cargo build is not run here'\n",
    );
    let named = compile_lines(&planted, "p");
    assert_eq!(named.len(), 4, "planted compiles: {named:?}");
    assert!(named[0].contains("cargo nextest run") && named[1].contains("cargo +nightly build"));
    assert!(named[2].contains("cargo --locked nextest") && named[3].contains("never check"));
}

#[test]
fn containment_failure_diagnostic_does_not_assign_a_cause_from_load() {
    let justfile = justfile_text();
    let body = recipe_body(&justfile, "gate-containment").unwrap();
    assert!(!body.contains("A HealthTimeout at high load is that"));
    assert!(!body.contains("NOT load-shaped"));
    assert!(body.contains("cause remains unresolved"));
    assert!(body.contains("does not explain the original failure"));
}

/// The writer measurement pass is load-sensitive by construction (11-32 s measured
/// across three green push tiers on one host), so it is an L2 step. It is
/// required NIGHTLY — `gate-nightly` must reach it structurally, after a
/// `quiet-box-wait` — and no L1 tier runs it; its correctness half
/// (`persistent_current_writer_lifecycle_is_verified_by_raw_sql_after_reopen`) stays in
/// the default suite (see `NIGHTLY_CELLS`). The pass itself is untouched.
#[test]
fn full_gates_require_a_separate_writer_measurement_pass() {
    let justfile = justfile_text();
    assert!(
        structurally_required_recipes(&justfile, "gate-nightly").contains_key("test-measurement"),
        "`gate-nightly` must reach `test-measurement`"
    );
    for tier in ["gate", "gate-push"] {
        assert!(
            !reachable_recipes(&justfile, tier).contains_key("test-measurement"),
            "`{tier}` reaches `test-measurement`, which is an L2 step"
        );
    }
    let nightly = recipe_body(&justfile, "gate-nightly").unwrap();
    let measurement_at =
        line_index(&nightly, "just test-measurement").expect("required measurement pass");
    assert!(
        nightly
            .lines()
            .take(measurement_at)
            .any(|line| line.trim() == "just quiet-box-wait"),
        "`gate-nightly` must wait for a quiet box before the measurement pass"
    );
    let measurement = recipe_body(&justfile, "test-measurement").expect("measurement recipe");
    assert!(
        line_index(
            &measurement,
            "cargo nextest run --workspace -P measurement --test-threads 1"
        )
        .is_some()
    );
    assert!(!measurement.contains("--run-ignored"));
}

/// `just gate` must SAY that it does not prove containment.
///
/// A green whose scope nobody states will be read as "everything is fine". The gate is
/// host-independent by construction and cannot see a containment regression, so it names
/// the lane that can. This is the cheapest half of closing the blind spot and the half
/// most likely to be deleted as noise.
/// The commit tier also leaves FOUR more proofs unrun (release self-test, footprint,
/// soak, measurement) on top of containment, so it must name the tier that runs them.
/// Required-ness is still achieved by naming rather than by concatenation, and this is
/// the assertion that makes the naming non-optional.
#[test]
fn the_gate_names_the_containment_it_does_not_prove() {
    let justfile = justfile_text();
    let body = recipe_body(&justfile, "gate").expect("a `gate` recipe exists");
    for named in ["gate-containment", "gate-push"] {
        assert!(
            body.contains(named),
            "the commit tier must name `{named}` — the required work it does not itself run \
             — in its own output. Body:\n{body}"
        );
    }
    // The push tier names the L2 tier that runs what L1 leaves out.
    let push = recipe_body(&justfile, "gate-push").expect("a `gate-push` recipe exists");
    assert!(
        push.contains("gate-nightly"),
        "the push tier must name `gate-nightly` — the required L2 work it does not run — in \
         its own output. Body:\n{push}"
    );
}

/// The containment lane must reach every containment proof.
///
/// "Reach" here is deliberately structural: each proof must be named by a
/// top-level standalone call or Just header dependency. This rejects echo-only
/// and conditional-only coverage, but it is not a runtime execution receipt.
///
/// THE DEFECT THIS PINS. `just gate` contains zero smoke, adversarial, or live steps.
/// With no CI it is the only automatic gate, and that blindness has a receipt: four
/// `smoke_main_local_socket_*` tests grepped for a string the product does not emit and
/// stayed red for a feature's whole lifetime because nothing ran them. Five containment
/// recipes existed, all correct, and no automatic step invoked any of them.
///
/// COUNTERFACTUAL: drop any one line from `gate-containment` and this names it.
#[test]
fn the_containment_lane_reaches_every_containment_proof() {
    let justfile = justfile_text();
    let reachable = structurally_required_recipes(&justfile, "gate-containment");

    for proof in CONTAINMENT_PROOFS {
        assert!(
            reachable.contains_key(*proof),
            "`gate-containment` no longer reaches `{proof}`; reachable: {:?}",
            reachable.keys().collect::<Vec<_>>()
        );
    }

    for proof in CONTAINMENT_PRODUCT_PATH_PROOFS {
        assert!(
            reachable.contains_key(*proof),
            "`gate-containment` no longer reaches the product-path proof `{proof}`. It is \
             in no other lane — `just verify` runs it only when the diff touches \
             `bin/kata/src/cli/**` — so dropping it here makes it unrun, which is \
             the state it was in when it sat red on main. Reachable: {:?}",
            reachable.keys().collect::<Vec<_>>()
        );
    }

    // One code path, two callers: the lane's entry gate and the operator's pre-flight.
    // Two copies of a precondition list is the ambiguous-name defect in its most
    // expensive form — a `host-check` that answers a different question from the lane it
    // claims to pre-flight, discovered 25 minutes into the lane.
    assert!(
        reachable.contains_key("_containment-preconditions"),
        "`gate-containment` must gate on `_containment-preconditions`; reachable: {:?}",
        reachable.keys().collect::<Vec<_>>()
    );
    let host_check = recipe_body(&justfile, "host-check").expect("a `host-check` recipe exists");
    assert!(
        line_index(&host_check, "just _containment-preconditions").is_some(),
        "`host-check` must run the SAME `_containment-preconditions` the lane gates on, \
         so an operator can learn in seconds what they would otherwise learn in 25 \
         minutes. Body:\n{host_check}"
    );
}

/// Inside the containment lane, a capability SKIP must be a FAILURE.
///
/// THE DEFECT THIS PINS is the whole reason the lane exists: a capability probe
/// that fails on a host (for example a `/usr`-only bind on a merged-usr host)
/// turns every live test it gates into a SKIP, and the harness reports a skip as a
/// pass. A containment suite that certifies by not running is worse than no suite.
///
/// COUNTERFACTUAL: delete `KATA_SANDBOX_REQUIRE_LIVE=1` from any sandbox recipe, or
/// `KATA_LIVE_SMOKE` from `smoke-no-budget`, and this names the recipe.
#[test]
fn a_capability_skip_is_a_failure_inside_the_containment_lane() {
    let justfile = justfile_text();

    for recipe in [
        "oci-live-smoke",
        "nightly-oci-live",
        "recovery-checkpoint-live",
    ] {
        let body =
            body_with_calls(&justfile, recipe).unwrap_or_else(|| panic!("`{recipe}` exists"));
        assert!(
            body.contains("KATA_SANDBOX_REQUIRE_LIVE=1"),
            "`{recipe}` rides the required containment lane, so a host-capability SKIP \
             must be a FAILURE there: it must set KATA_SANDBOX_REQUIRE_LIVE=1. \
             Body:\n{body}"
        );
    }

    // The product-path half. These tests early-return unless KATA_LIVE_SMOKE is set,
    // and an early return is reported as a pass — the same defect wearing shell clothes.
    // BOTH entry points, not just the lane's: `smoke` is the maintainer's hand-run door onto
    // the same binaries (it is how the two model-budget smokes are invoked at all), and
    // a knob that is only right on the automatic path is the half nobody re-checks.
    for recipe in ["smoke", "smoke-no-budget"] {
        let body =
            body_with_calls(&justfile, recipe).unwrap_or_else(|| panic!("`{recipe}` exists"));
        assert!(
            body.contains("KATA_LIVE_SMOKE=1"),
            "`{recipe}` must set KATA_LIVE_SMOKE=1; without it every smoke returns early \
             and the lane certifies nothing. Body:\n{body}"
        );
    }
}

/// The containment lane is a SEPARATE required step, and this records why in the one
/// place that can enforce it.
///
/// Every containment proof needs `--run-ignored` (`only`, or `all` for a
/// capability-conditional binary), because `#[ignore]` is exactly what
/// keeps a host-dependent test out of `just test`.
/// `gate_static_recipe_graph_excludes_the_live_eval_tier` asserts the modelled gate graph
/// contains no `--run-ignored` at all. Those two facts are not in
/// tension — together they are the argument: the lane cannot be folded into `gate` without
/// deleting the gate's guarantee that an unattended run never widens a filter into
/// budget-spending ignored tests. Asserting BOTH directions stops a future
/// "simplification" from merging them, and stops the lane from quietly becoming a no-op
/// that would satisfy the exclusion test by running nothing.
#[test]
fn the_containment_lane_runs_ignored_tests_and_the_gate_still_does_not() {
    let justfile = justfile_text();

    let lane_bodies = reachable_recipes(&justfile, "gate-containment")
        .into_values()
        .collect::<String>();
    assert!(
        lane_bodies.contains("--run-ignored"),
        "the containment lane must run the `#[ignore]`d host-capability tests — that is \
         what it is for, and it is why it cannot live inside `gate`"
    );

    let gate_reachable = reachable_recipes(&justfile, "gate");
    for proof in CONTAINMENT_PROOFS {
        assert!(
            !gate_reachable.contains_key(*proof),
            "the COMMIT tier now reaches `{proof}`, which runs ignored tests. Either the \
             commit tier lost its host-independence or its no-run-ignored guarantee is \
             about to break; keep the containment proofs in `gate-containment`."
        );
    }

    // The push tier is what makes containment required, so the edge from `gate-push` to
    // `gate-containment` is the thing that must not be deletable: without it, "required
    // before push" would rest on prose.
    assert!(
        structurally_required_recipes(&justfile, "gate-push").contains_key("gate-containment"),
        "`gate-push` must reach `gate-containment` by a top-level standalone call — that \
         edge IS containment's required-ness before push."
    );
}

// ───────────────────────────────────────────────────────────────────────────────
// L2 — THE NIGHTLY DEEP TIER (AGENTS.md, "Four gate layers").
//
// L1 (`gate` + `gate-push`) is required before every push; L2 (`gate-nightly`) is
// required nightly on main. A cell moved from L1 to L2 only if it is bound by a real
// timer or by host load, costs ~10 s or more, AND its logic is also pinned by a
// host-free twin `just test` runs on every commit. The checks below hold three things:
// the L2 tier exists and no L1 tier reaches it; every moved cell leaves L1 for EXACTLY
// L2 (no cell in both, none in neither); and every moved cell names twins that are real,
// non-ignored, default-suite tests in files that cannot capability-skip.
// ───────────────────────────────────────────────────────────────────────────────

/// The recipes `gate-nightly` must keep reaching, none of which an L1 tier may reach.
/// `model-check-0003`'s 76 TLC runs took 2390 s at 16 workers under a load of 100 to 150,
/// and only its own files, its runner and the TLC pin can change a verdict: `just verify`
/// routes those diffs to it, and L2 re-runs it whole.
const NIGHTLY_PROOFS: &[&str] = &[
    "deny-fresh",
    "test-measurement",
    "nightly-oci-live",
    "recovery-checkpoint-live",
    "cold-build",
    "flake-checks",
    "model-check-0003",
];

/// How a moved cell is selected in L2.
enum NightlyRoute {
    /// Subtracted from its L1 step with `not test(=NAME)` and selected by an L2 step with
    /// `test(=NAME)`, inside this nextest binary.
    Binary(&'static str),
    /// Owned whole by this L2 recipe (the checkpoint trio's exact `kind(lib)` route, the
    /// measurement profile), which no L1 tier reaches.
    Recipe(&'static str),
}

/// One cell the push tier gave to L2.
struct NightlyCell {
    /// Repo-relative source file declaring the cell.
    source: &'static str,
    route: NightlyRoute,
    /// The test fn name.
    test: &'static str,
    /// What its wall time is bound by, measured from green push-tier logs.
    bound_by: &'static str,
    /// Host-free twins, `(repo-relative file, test fn)`: default-suite tests that pin the
    /// same logic on every commit.
    twins: &'static [(&'static str, &'static str)],
}

const NIGHTLY_CELLS: &[NightlyCell] = &[
    NightlyCell {
        source: "bin/kata/tests/oci_main_live.rs",
        route: NightlyRoute::Binary("oci_main_live"),
        test: "a_capsule_past_120_seconds_completes_on_its_own_wall_clock_live",
        bound_by: "133-136 s: a `sleep 130` capsule under `timeout_ms = 180000`, by design",
        twins: &[
            (
                "crates/worker/tests/provider_supervisor.rs",
                "a_capsule_provider_waits_the_capsules_own_wall_clock",
            ),
            (
                "crates/worker/tests/oci_driver_refusals.rs",
                "the_capsule_route_launches_its_provider_with_the_capsules_own_wall_clock",
            ),
            (
                "crates/workflow/tests/capsule_assembly.rs",
                "the_three_mappings_are_work_out_and_tmp_over_the_declared_trees",
            ),
        ],
    },
    NightlyCell {
        source: "crates/workflow/tests/oci_stage_live.rs",
        route: NightlyRoute::Binary("oci_stage_live"),
        test: "a_capsule_past_its_wall_clock_is_stopped_by_its_provider_budget_live",
        bound_by: "36 s: `timeout_ms = 5000` plus the 30 s PROVIDER_FRAME_MARGIN before the \
                   provider kills a `sleep 60` guest",
        twins: &[
            (
                "crates/worker/tests/provider_assignment_deadline.rs",
                "an_acceptance_and_a_completion_share_the_assignments_one_deadline",
            ),
            (
                "crates/worker/tests/provider_assignment_deadline.rs",
                "a_provider_that_never_reads_its_assignment_is_cut_off_at_the_deadline",
            ),
            (
                "crates/worker/tests/provider_supervisor.rs",
                "a_capsule_provider_waits_the_capsules_own_wall_clock",
            ),
        ],
    },
    NightlyCell {
        source: "bin/kata/src/cli/recovery_capture/checkpoint_live_tests.rs",
        route: NightlyRoute::Recipe("recovery-checkpoint-live"),
        test: "checkpoint_source_loss_resumes_real_timer_and_successor_once_across_two_main_processes",
        bound_by: "25 s: a 15 s durable `sleep` that must fire across two main processes",
        twins: &[
            (
                "crates/workflow/tests/oci_check_and_dispatch.rs",
                "a_durable_sleep_parks_main_side_and_releases_its_successor_after_the_deadline",
            ),
            (
                "crates/core/src/store/backup/checkpoint_files_tests.rs",
                "checkpoint_files_source_loss_restores_bytes_modes_empty_dirs_and_deletions",
            ),
            (
                "bin/kata/src/cli/recovery_references/cohort.rs",
                "checkpoint_binding_refuses_changed_cut_program_attempt_and_deadline",
            ),
            (
                "crates/core/tests/backup_recovery_v4.rs",
                "checkpoint_origin_evidence_survives_a_second_backup_with_deep_and_staging_like_names",
            ),
        ],
    },
    NightlyCell {
        source: "bin/kata/src/cli/recovery_capture/checkpoint_live_tests.rs",
        route: NightlyRoute::Recipe("recovery-checkpoint-live"),
        test: "checkpoint_preserves_previously_validated_candidate_revalidates_and_lands_after_source_loss",
        bound_by: "23-24 s: the same 15 s durable `sleep`",
        twins: &[
            (
                "crates/vcs/tests/recovery_references.rs",
                "recovery_execution_workspace_restores_exact_source_commit_after_source_loss",
            ),
            (
                "crates/workflow/tests/promotion_candidate_coherence.rs",
                "revalidating_all_required_proofs_rotates_the_pin_but_partial_revalidation_does_not",
            ),
            (
                "crates/vcs/tests/jj_backend.rs",
                "jj_promote_parks_rebased_candidate_fail_closed_until_revalidated",
            ),
        ],
    },
    NightlyCell {
        source: "bin/kata/src/cli/recovery_capture/checkpoint_live_tests.rs",
        route: NightlyRoute::Recipe("recovery-checkpoint-live"),
        test: "checkpoint_refuses_native_landing_when_restored_candidate_changes_after_revalidation",
        bound_by: "24 s: the same 15 s durable `sleep`",
        twins: &[
            (
                "crates/vcs/tests/candidate_tree_pin.rs",
                "a_candidate_edited_after_the_stamp_is_refused_with_both_trees_named",
            ),
            (
                "crates/types/tests/candidate_tree_pin_refusals.rs",
                "a_mismatch_refuses_and_names_both_trees",
            ),
        ],
    },
    NightlyCell {
        source: "crates/core/tests/operational_write_measurement.rs",
        route: NightlyRoute::Recipe("test-measurement"),
        test: "persistent_current_writer_reports_serialized_transaction_latency_and_throughput",
        bound_by: "11-30 s: 6,400 FULL-sync commits; the spread across three green runs is \
                   disk load",
        twins: &[(
            "crates/core/tests/operational_write_measurement.rs",
            "persistent_current_writer_lifecycle_is_verified_by_raw_sql_after_reopen",
        )],
    },
];

/// Does `[profile.default] default-filter` — `not ( A | B | ... )`, one disjunct per line
/// — exclude test `test` of binary `binary`? A disjunct excludes it when every kind of
/// clause it has matches: its `binary(...)` names (exact either way) and its `test(...)`
/// matchers (`test(NAME)` a substring, `test(=NAME)` exact). Only the shapes that filter
/// uses; anything else in a disjunct makes it match nothing here, and the synthetic
/// cases below pin the four shapes it does use.
fn default_filter_excludes(filter: &str, binary: &str, test: &str) -> bool {
    fn args<'a>(clause: &'a str, head: &str) -> Vec<&'a str> {
        clause
            .match_indices(head)
            .filter_map(|(at, _)| {
                let rest = &clause[at + head.len()..];
                rest.find(')').map(|close| &rest[..close])
            })
            .collect()
    }
    let inner = filter
        .trim()
        .strip_prefix("not")
        .map(str::trim)
        .and_then(|rest| rest.strip_prefix('('))
        .and_then(|rest| rest.trim_end().strip_suffix(')'))
        .unwrap_or_else(|| panic!("default-filter is not `not ( ... )`: {filter}"));
    inner
        .split('|')
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .any(|clause| {
            let binaries = args(clause, "binary(");
            let tests = args(clause, "test(");
            let binary_matches = binaries
                .iter()
                .all(|name| name.trim_start_matches('=') == binary);
            let test_matches = tests.iter().all(|matcher| match matcher.strip_prefix('=') {
                Some(exact) => exact == test,
                None => test.contains(matcher),
            });
            (!binaries.is_empty() || !tests.is_empty()) && binary_matches && test_matches
        })
}

#[test]
fn the_default_filter_reader_excludes_exactly_what_nextest_would() {
    let filter = "not (\n    test(giant_soak)\n    | binary(whole_soak)\n    | (binary(=pair) & test(=pair_measurement))\n)";
    assert!(default_filter_excludes(filter, "any", "a_giant_soak_test"));
    assert!(default_filter_excludes(filter, "whole_soak", "anything"));
    assert!(default_filter_excludes(filter, "pair", "pair_measurement"));
    assert!(!default_filter_excludes(
        filter,
        "pair",
        "pair_correctness_fixture"
    ));
    assert!(!default_filter_excludes(
        filter,
        "other",
        "pair_measurement"
    ));
    assert!(!default_filter_excludes(filter, "any", "ordinary"));
}

/// Every exact test name the recipes reachable from `root` use, negated or not.
fn exact_names_reachable(justfile: &Justfile, root: &str, negated: bool) -> BTreeSet<String> {
    reachable_recipes(justfile, root)
        .values()
        .flat_map(|body| exact_test_names(body, negated))
        .collect()
}

/// L2 exists, is structurally required, and no L1 tier reaches any of it.
///
/// REFUSED: a `gate-nightly` that does not structurally reach one of `NIGHTLY_PROOFS`;
/// `gate` or `gate-push` possibly reaching one (a moved step would then run twice, and
/// the timer-bound cost L2 exists to take off the push path would be back on it).
#[test]
fn the_nightly_tier_reaches_every_nightly_proof_and_neither_l1_tier_does() {
    let justfile = justfile_text();
    let nightly = structurally_required_recipes(&justfile, "gate-nightly");
    for proof in NIGHTLY_PROOFS {
        assert!(
            nightly.contains_key(*proof),
            "`gate-nightly` no longer reaches `{proof}`; reachable: {:?}",
            nightly.keys().collect::<Vec<_>>()
        );
    }
    for tier in ["gate", "gate-push"] {
        let reachable = reachable_recipes(&justfile, tier);
        for proof in NIGHTLY_PROOFS {
            assert!(
                !reachable.contains_key(*proof),
                "the L1 tier `{tier}` reaches the L2 step `{proof}`"
            );
        }
    }
    // The L2 tier takes the host first, like the push tier, and runs its live steps under
    // the lane lock like the containment lane.
    let body = recipe_body(&justfile, "gate-nightly").unwrap();
    assert!(body.contains("exec scripts/installed-main-lock.sh just gate-nightly"));
    let first_build = line_index(&body, "just test-build").expect("gate-nightly builds");
    for host in ["just pgrep-stale", "just _containment-preconditions"] {
        assert!(
            line_index(&body, host).unwrap_or_else(|| panic!("`gate-nightly` lost `{host}`"))
                < first_build,
            "`gate-nightly` builds before `{host}`"
        );
    }
}

/// THE SPLIT IS EXACT: every cell the push tier gave to L2 leaves L1 for exactly L2.
///
/// REFUSED, each by name: an L1 `not test(=NAME)` subtraction that no
/// `NIGHTLY_CELLS` row claims (a cell dropped from the push tier with no recorded
/// disposition); a `NIGHTLY_CELLS`
/// binary-route row whose cell L1 still runs, or that L2 does not select; an L2 exact
/// selection no row claims; an L2 live step that is not narrowed to exact names (it would
/// re-run the push tier's cells); the push tier positively naming an L2 cell; a
/// recipe-route row whose recipe does not select it or that the push tier reaches; a
/// binary-route cell that is not `#[ignore]`d; and a twin that is missing, `#[ignore]`d,
/// excluded from the default suite, or in a file that can capability-skip.
///
/// COUNTERFACTUALS: exercised below on synthetic bodies — an L1 subtraction with no L2
/// selection, and an L2 selection with no L1 subtraction, each name the cell.
#[test]
fn the_nightly_cells_leave_the_push_tier_for_exactly_the_nightly_tier() {
    let justfile = justfile_text();
    let binaries = workspace_test_binaries();

    let binary_cells: BTreeSet<String> = NIGHTLY_CELLS
        .iter()
        .filter(|cell| matches!(cell.route, NightlyRoute::Binary(_)))
        .map(|cell| cell.test.to_string())
        .collect();
    assert!(
        binary_cells.len() >= 2,
        "NON-VACUITY: only {} binary-route nightly cells",
        binary_cells.len()
    );
    // Two binary-route cells are the correct population until a new timer-bound
    // cell earns the tier move.

    // L1 subtracts exactly the binary-route cells (each `not test(=...)` hands a
    // cell to L2); L2 selects exactly the binary-route cells (plus the
    // recipe-route cells its own exact routes name).
    let l1_subtracted = exact_names_reachable(&justfile, "gate-push", true);
    assert_eq!(
        l1_subtracted, binary_cells,
        "the push tier's `not test(=...)` subtractions disagree with NIGHTLY_CELLS"
    );
    let l2_selected = exact_names_reachable(&justfile, "gate-nightly", false);
    let l2_binary_selected: BTreeSet<String> = l2_selected
        .iter()
        .filter(|name| !name.contains("::"))
        .cloned()
        .collect();
    assert_eq!(
        l2_binary_selected, binary_cells,
        "`gate-nightly`'s `test(=...)` selections and NIGHTLY_CELLS disagree"
    );
    assert!(
        exact_names_reachable(&justfile, "gate-nightly", true).is_empty(),
        "an L2 step SUBTRACTS a cell; L2 selects by exact name only"
    );
    let l1_selected = exact_names_reachable(&justfile, "gate-push", false);
    for cell in NIGHTLY_CELLS {
        assert!(
            !l1_selected.iter().any(|name| names_test(name, cell.test)),
            "the push tier positively selects the L2 cell `{}`",
            cell.test
        );
    }

    // Every L2 live step is narrowed to exact names: nothing in L2 runs a whole binary.
    for (recipe, body) in reachable_recipes(&justfile, "gate-nightly") {
        if body.contains("--run-ignored") {
            assert!(
                !exact_test_names(&body, false).is_empty(),
                "the L2 step `{recipe}` runs ignored tests without naming them exactly, so it \
                 can re-run cells the push tier already runs:\n{body}"
            );
        }
    }

    let nextest =
        std::fs::read_to_string(repo_root().join(".config/nextest.toml")).expect("nextest config");
    let default_filter = nextest
        .split("default-filter = '''")
        .nth(1)
        .and_then(|rest| rest.split("'''").next())
        .expect("[profile.default] has a default-filter");
    let push_reachable = reachable_recipes(&justfile, "gate-push");

    for cell in NIGHTLY_CELLS {
        let source = std::fs::read_to_string(repo_root().join(cell.source))
            .unwrap_or_else(|e| panic!("{}: {e}", cell.source));
        assert!(
            source.contains(&format!("fn {}(", cell.test)),
            "`{}` is not a test in {}",
            cell.test,
            cell.source
        );
        assert!(!cell.bound_by.is_empty() && !cell.twins.is_empty());
        match cell.route {
            NightlyRoute::Binary(binary) => {
                assert_eq!(
                    binaries.get(binary).map(|path| path.to_str().unwrap()),
                    Some(cell.source),
                    "`{}`'s binary `{binary}` is not {}",
                    cell.test,
                    cell.source
                );
                assert!(
                    ignored_test_names(&source)
                        .iter()
                        .any(|name| name == cell.test),
                    "`{}` is selected by `--run-ignored`; it must be `#[ignore]`d",
                    cell.test
                );
            }
            NightlyRoute::Recipe(recipe) => {
                assert!(
                    !push_reachable.contains_key(recipe),
                    "`{}`'s L2 recipe `{recipe}` is reachable from the push tier",
                    cell.test
                );
                let selector = format!(
                    "{}\n{}",
                    body_with_calls(&justfile, recipe).unwrap_or_default(),
                    if recipe == "test-measurement" {
                        nextest
                            .split("[profile.measurement]")
                            .nth(1)
                            .unwrap_or_default()
                    } else {
                        ""
                    }
                );
                assert!(
                    selector.contains(cell.test),
                    "the L2 recipe `{recipe}` does not select `{}`",
                    cell.test
                );
            }
        }
        for (file, twin) in cell.twins {
            let twin_source = std::fs::read_to_string(repo_root().join(file))
                .unwrap_or_else(|e| panic!("`{}`'s twin file {file}: {e}", cell.test));
            assert!(
                twin_source.contains(&format!("fn {twin}(")),
                "`{}` names the twin `{twin}`, which is not a test in {file}",
                cell.test
            );
            assert!(
                !ignored_test_names(&twin_source)
                    .iter()
                    .any(|name| name == twin),
                "`{}`'s twin `{twin}` is `#[ignore]`d, so no commit runs it",
                cell.test
            );
            let markers: Vec<&str> = LIVE_CAPABILITY_MARKERS
                .iter()
                .map(|(marker, _)| *marker)
                .filter(|marker| twin_source.contains(marker))
                .collect();
            assert!(
                markers.is_empty(),
                "`{}`'s twin file {file} carries capability-skip markers {markers:?}: a twin \
                 that can skip is not host-free",
                cell.test
            );
            let stem = Path::new(file).file_stem().and_then(OsStr::to_str).unwrap();
            assert!(
                !default_filter_excludes(default_filter, stem, twin),
                "`{}`'s twin `{twin}` is excluded from the default suite by \
                 `[profile.default] default-filter`",
                cell.test
            );
        }
    }

    // The counterfactuals: a subtraction nothing selects, and a selection nothing
    // subtracted, both show up as a disagreement between the two exact-name sets.
    let orphaned = parse_justfile_source(
        "l1:\n    cargo nextest run --workspace -E 'binary(b) & not test(=gone_cell_live)'\n\nl2:\n    echo nothing\n",
    );
    assert_eq!(
        exact_names_reachable(&orphaned, "l1", true),
        BTreeSet::from(["gone_cell_live".to_string()])
    );
    assert!(exact_names_reachable(&orphaned, "l2", false).is_empty());
    let doubled = parse_justfile_source(
        "l2:\n    cargo nextest run --workspace --run-ignored all -E 'binary(b) & test(=twice_live)'\n",
    );
    assert_eq!(
        exact_names_reachable(&doubled, "l2", false),
        BTreeSet::from(["twice_live".to_string()])
    );
    assert!(exact_names_reachable(&doubled, "l2", true).is_empty());
}

/// Each L2 live step runs `#[ignore]`d cells, so it must pass `--run-ignored`.
#[test]
fn every_nightly_live_step_runs_ignored_tests() {
    let justfile = justfile_text();
    for recipe in ["nightly-oci-live", "recovery-checkpoint-live"] {
        let body =
            body_with_calls(&justfile, recipe).unwrap_or_else(|| panic!("`{recipe}` exists"));
        let folded = body.replace("\\\n", " ");
        let lines: Vec<&str> = folded
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with('#') && line.contains("cargo nextest run"))
            .collect();
        assert!(!lines.is_empty(), "`{recipe}` runs no nextest");
        for line in lines {
            assert!(
                line.contains("--run-ignored all"),
                "`{recipe}` does not pass `--run-ignored all`: {line}"
            );
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────────
// CONTAINMENT COVERAGE — the blind spot BETWEEN the two required lanes.
//
// `just gate` is host-independent and `just gate-containment` proves containment on
// this kernel, and between them they are meant to leave nothing unrun. They do not,
// and the reason is structural rather than an oversight: the containment lane's reach
// is a HAND-MAINTAINED UNION OF EXACT `binary(...)` FILTERS spread across five
// separate recipes. nextest's `binary(...)` is an exact match, so that union is
// correct about every binary it names and SILENT about every binary it does not.
//
// A test binary that can decline to assert for a host reason and is named by none of
// those filters is therefore run by neither required lane in any meaningful sense:
// `just gate` executes it and reads its capability skip as a PASS, and the one lane
// that would refuse the skip (`KATA_SANDBOX_REQUIRE_LIVE=1`) never selects it. Both
// lanes go green having measured nothing.
//
// The shape that lands a binary there is a private capability probe followed by a
// bare `eprintln!(...); return;`: the test reports a pass on a host where it measured
// nothing, and no filter names it to make that skip a failure.
//
// The rule these checks enforce: DERIVE BOTH SIDES. The set of capability-conditional
// test binaries is read off the tree; the set of selected binaries is read off the
// justfile's own recipe graph. Neither list is transcribed, because hand-carried
// numbers drift. The marker set that defines
// "capability-conditional" is `common::LIVE_CAPABILITY_MARKERS`, shared with the
// protected-property ledger's checker.
// ───────────────────────────────────────────────────────────────────────────────

/// Test binaries that are capability-conditional and deliberately ride NEITHER lane.
///
/// This is the "declare or cover" half, and it is what makes a NEW such binary fail
/// the gate rather than pass silently: there is no third option. An entry must state
/// WHICH lane owns it instead, because "not containment" is not a reason.
///
/// Every entry is re-checked below — a row that stopped applying FAILS. An allowlist
/// nobody prunes becomes the thing it was protecting against.
const CAPABILITY_CONDITIONAL_OUTSIDE_THE_LANE: &[(&str, &str)] = &[
    (
        "node_environment_binding",
        "its one ignored test, `daemon_cell_child`, is the CHILD-PROCESS half of \
         `a_dead_or_hung_nix_daemon_refuses_boot_by_name_within_the_deadline`, re-executed by \
         that parent with --exact --include-ignored and a private NIX_REMOTE. The parent runs \
         in just test and FAILS (never skips) on a host without nix; the child is not an \
         optional host-capability proof.",
    ),
    (
        "git_config_hooks",
        "its one ignored test, `kata_operations_under_a_hostile_global_config`, is the \
         CHILD-PROCESS half of `kata_git_children_run_no_hook_from_any_configuration`, \
         re-executed by that parent with --exact --ignored and a private GIT_CONFIG_GLOBAL. \
         The parent runs in just test and FAILS (never skips) when the child does not pass; \
         the child is not an optional host-capability proof.",
    ),
    (
        "recovery_references",
        "its ignored upstream-jj lock CHILD-PROCESS fixture is re-executed by the \
         sibling lock tests with --exact --ignored. Those parent tests run in \
         just test; the child is not an optional host-capability proof.",
    ),
    (
        "nanocode_live",
        "N6's live acceptance of the embedded harness on REAL providers: \
         `nanocode_openai` × kata's own ChatGPT login (`kata login openai`) and \
         `nanocode_anthropic` × the operator's `env:ANTHROPIC_API_KEY`, through real nodes \
         and rootless-youki capsules — MODEL BUDGET, which a maintainer spends by hand. \
         Every cell PANICS with the named host fact (a missing key, a refused login, an \
         uncertified youki) rather than skipping. Its no-spend twin, \
         `nanocode_interruption_live`, rides `oci-live-smoke`. Run by: `just live-nanocode`, \
         by hand, never by an unattended lane.",
    ),
    (
        "e3_crash_matrix_host_live",
        "E3's HOST column (D2 §5.4): P1-P4 with the WHOLE machine killed through \
         `KATA_E3_HOST_KILL_CMD` while the armed process is stopped at its point, then \
         resumed after the machine restarts on the same disk (`KATA_E3_HOST_RESUME`). It \
         needs a machine to kill, which no lane has, and a provider-backed nanocode agent \
         (it refuses the mock, which the machine's kill ends); its process-column twins \
         (`e3_crash_matrix_live`) ride the containment lane in `oci-live-smoke` on the \
         mock. Its arm phase has run only against a stand-in kill command and its resume \
         phase never. Every cell PANICS (a VOID or a refusal naming the missing command) \
         rather than skipping. Run by: hand, on the VM, never by an unattended lane.",
    ),
];

/// Every integration-test binary in the workspace: binary name -> repo-relative path.
///
/// Keyed by file stem, the name nextest's `binary(...)` matches, so two crates
/// owning a `smokes.rs` yield one entry; [`workspace_test_roots`] keeps both.
fn workspace_test_binaries() -> BTreeMap<String, PathBuf> {
    workspace_test_roots()
        .into_iter()
        .filter_map(|path| {
            let name = path.file_stem().and_then(OsStr::to_str)?.to_string();
            Some((name, path))
        })
        .collect()
}

/// The root file of every integration-test target in the workspace, repo-relative.
///
/// A `*.rs` file DIRECTLY inside a `tests/` directory whose parent holds a
/// `Cargo.toml` is one cargo test target. Files in SUBdirectories of `tests/`
/// (`tests/common/mod.rs`) are plain modules, not targets, which is why the scan
/// does not recurse into them.
fn workspace_test_roots() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            if path.file_name() == Some(OsStr::new("target")) {
                continue;
            }
            if path.file_name() == Some(OsStr::new("tests"))
                && path
                    .parent()
                    .is_some_and(|package| package.join("Cargo.toml").is_file())
            {
                out.push(path.clone());
            }
            walk(&path, out);
        }
    }

    let root = repo_root();
    let mut test_dirs = Vec::new();
    walk(&root.join("crates"), &mut test_dirs);
    walk(&root.join("bin"), &mut test_dirs);

    let mut roots = Vec::new();
    for dir in test_dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension() != Some(OsStr::new("rs")) || !path.is_file() {
                continue;
            }
            roots.push(
                path.strip_prefix(&root)
                    .unwrap_or(path.as_path())
                    .to_path_buf(),
            );
        }
    }
    roots.sort();
    roots
}

/// Every source file the test target rooted at `root` (repo-relative) compiles: the
/// root and each file its `mod` items reach, inline modules and `#[path]`
/// attributes included, by the reference's module-path rules
/// ([`common::rust_tree::module_source`]); repo-relative and normalised lexically
/// (`.` dropped, `..` popping a component). A `mod` whose file is absent (behind a
/// `cfg` this host does not build) reaches nothing. Not seen, stated: a module a
/// macro expands to, and text an `include!` pastes in.
fn module_files(root: &Path) -> BTreeSet<PathBuf> {
    fn visit(
        cache: &mut SourceCache,
        items: &[syn::Item],
        dirs: &ModuleDirs,
        files: &mut BTreeSet<PathBuf>,
    ) {
        for item in items {
            let syn::Item::Mod(declared) = item else {
                continue;
            };
            match module_source(dirs, declared) {
                ModuleSource::Inline(inline, inner) => visit(cache, inline, &inner, files),
                ModuleSource::File(child, inner) => {
                    let Ok(parsed) = cache.parse(&child) else {
                        continue;
                    };
                    let child_items = parsed.items.clone();
                    if files.insert(repo_relative(&child)) {
                        visit(cache, &child_items, &inner, files);
                    }
                }
            }
        }
    }
    let absolute = repo_root().join(root);
    let mut cache = SourceCache::default();
    let items = cache
        .parse(&absolute)
        .unwrap_or_else(|error| panic!("test root {}: {error}", root.display()))
        .items
        .clone();
    let mut files = BTreeSet::from([root.to_path_buf()]);
    visit(&mut cache, &items, &root_dirs(&absolute), &mut files);
    files
}

/// `path` relative to the repository, with `.` dropped and each `..` popping a
/// component.
fn repo_relative(path: &Path) -> PathBuf {
    let mut resolved = PathBuf::new();
    for component in path.strip_prefix(repo_root()).unwrap_or(path).components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            other => resolved.push(other),
        }
    }
    resolved
}

/// How many of the workspace's test targets compile each source file
/// ([`module_files`] of every [`workspace_test_roots`] root).
fn module_file_owners() -> &'static BTreeMap<PathBuf, usize> {
    static OWNERS: OnceLock<BTreeMap<PathBuf, usize>> = OnceLock::new();
    OWNERS.get_or_init(|| {
        let mut owners = BTreeMap::new();
        for root in workspace_test_roots() {
            for file in module_files(&root) {
                *owners.entry(file).or_insert(0) += 1;
            }
        }
        owners
    })
}

/// The source files the test binary rooted at `root` (repo-relative) compiles of
/// its OWN: the root, then every other [`module_files`] file no other test target
/// of the workspace compiles, in path order. The small suites folded into a
/// binary as `#[path]` modules (owner decision #12) are read wherever they are
/// kept, because the root's module tree reaches them, and a `*.rs` file no
/// module declares is not. A module two or more targets compile (`tests/common/`,
/// a shared fixture or rig) belongs to no one binary and is not read.
fn binary_files(root: &Path) -> Vec<PathBuf> {
    let owners = module_file_owners();
    std::iter::once(root.to_path_buf())
        .chain(
            module_files(root)
                .into_iter()
                .filter(|file| file != root && owners.get(file) == Some(&1)),
        )
        .collect()
}

/// The text of every [`binary_files`] file of the binary rooted at `root`, joined
/// by newlines: what a guard classifying the BINARY reads.
fn binary_source(root: &Path) -> std::io::Result<String> {
    let mut texts = Vec::new();
    for file in binary_files(root) {
        texts.push(std::fs::read_to_string(repo_root().join(file))?);
    }
    Ok(texts.join("\n"))
}

/// **Every test binary that installs kata's Code Mode limits invokes the
/// interpreter entry.** A test binary whose Code Mode cells run behind kata's
/// backend re-executes itself as their interpreter, so it carries the entry
/// (`kata_code_mode_host::interpreter_entry!`); one without it fails each cell,
/// "could not start", once a nanocode turn runs there. Refused: a workspace test
/// root whose [`binary_source`] code (lines not starting with `//`) calls
/// `kata_agent_nanocode::install_code_mode_limits()` or builds
/// `kata_worker::adapter_registry::production` (which calls it) and does not
/// invoke `interpreter_entry!()`. Not seen, stated: a crate's own unit tests
/// (`src/`), a module two or more test targets compile (`tests/common/`), and a
/// binary that reaches the installer only through another crate's code (a worker
/// a rig runs in-process builds the production registry in
/// `kata_worker::capsule_route`).
///
/// **Would red if:** such a binary lacked the entry (watched: the three worker
/// and workflow roots that build the production registry, before they carried
/// it; and a folded suite calling the installer from a module kept outside
/// `tests/<stem>/`).
#[test]
fn every_test_binary_that_installs_kata_code_mode_invokes_the_interpreter_entry() {
    let roots = workspace_test_roots();
    assert!(
        roots.len() > 100,
        "the workspace's test roots: {}",
        roots.len()
    );
    // This file quotes all three spellings as data.
    let guard = this_guard_file();
    let missing: Vec<String> = roots
        .iter()
        .filter(|root| **root != guard)
        .filter(|root| {
            let source =
                binary_source(root).unwrap_or_else(|e| panic!("reading {}: {e}", root.display()));
            let code = source
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            let installs = code.contains("install_code_mode_limits()")
                || code.contains("adapter_registry::production");
            installs && !code.contains("interpreter_entry!()")
        })
        .map(|root| root.display().to_string())
        .collect();
    assert!(
        missing.is_empty(),
        "test binaries that install kata's Code Mode limits without the interpreter entry: \
         {missing:#?}"
    );
}

/// This file's own repo-relative path, derived rather than typed.
///
/// It has to be excluded from the scan because it QUOTES every marker in
/// [`LIVE_CAPABILITY_MARKERS`] as data — the guard would otherwise classify itself as
/// a live-capability test binary and demand the containment lane run it, which would
/// be a check satisfying itself with its own text.
///
/// Built from `CARGO_MANIFEST_DIR` + this file's basename so a rename or a move
/// cannot silently widen the scan; the caller asserts the result is actually present
/// among the discovered binaries.
fn this_guard_file() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let basename = Path::new(file!())
        .file_name()
        .expect("file!() always ends in a file name");
    let absolute = manifest.join("tests").join(basename);
    match absolute.strip_prefix(repo_root()) {
        Ok(relative) => relative.to_path_buf(),
        Err(_) => absolute,
    }
}

/// Which markers a source file carries, and whether it wears a real `#[ignore]`.
///
/// `#[ignore]` is tracked separately because it is a DIFFERENT exclusion mechanism
/// with the same consequence: the knob family means "runs but may decline to assert",
/// while `#[ignore]` means "does not run under `just test` at all". Matched as an
/// attribute at the start of a trimmed line, so the many doc comments in this
/// workspace that discuss `#[ignore]` in prose do not count.
fn capability_signals(source: &str) -> Vec<String> {
    let mut signals: Vec<String> = LIVE_CAPABILITY_MARKERS
        .iter()
        .filter(|(marker, _)| source.contains(marker))
        .map(|(marker, why)| format!("`{marker}` ({why})"))
        .collect();
    if source
        .lines()
        .any(|line| line.trim_start().starts_with("#[ignore"))
    {
        signals.push(
            "`#[ignore]` (excluded from `just test` entirely, so only a \
             `--run-ignored` lane can reach it)"
                .to_string(),
        );
    }
    signals
}

/// Every `binary(NAME)` named anywhere in the recipe graph rooted at `root`.
///
/// Derived from the justfile, never transcribed: the five recipes that carry these
/// filters today are reached through [`reachable_recipes`], so adding a sixth recipe
/// to the lane extends this set automatically and dropping one shrinks it.
fn selected_binaries(justfile: &Justfile, root: &str) -> BTreeSet<String> {
    let mut selected = BTreeSet::new();
    for body in reachable_recipes(justfile, root).values() {
        let mut rest = body.as_str();
        while let Some(at) = rest.find("binary(") {
            rest = &rest[at + "binary(".len()..];
            if let Some(close) = rest.find(')') {
                let name = &rest[..close];
                if !name.is_empty()
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                {
                    selected.insert(name.to_string());
                }
            }
        }
    }
    selected
}

/// The live roots of the two layers that run `#[ignore]`d tests: L1's containment lane
/// (reached from `gate-push`) and L2's nightly tier. Timer-bound cells move from the
/// first to the second, so "is this live test run by a
/// required layer" is a question about their UNION — and
/// `the_nightly_cells_leave_the_push_tier_for_exactly_the_nightly_tier` is what keeps the
/// union from double-running a cell.
const LIVE_LAYER_ROOTS: &[&str] = &["gate-containment", "gate-nightly"];

/// [`selected_binaries`] over both live layers.
fn live_layer_binaries(justfile: &Justfile) -> BTreeSet<String> {
    LIVE_LAYER_ROOTS
        .iter()
        .flat_map(|root| selected_binaries(justfile, root))
        .collect()
}

/// [`lane_test_filters`] over both live layers: a test is run iff SOME invocation in
/// EITHER layer selects it.
fn live_layer_filters(justfile: &Justfile) -> BTreeMap<String, Vec<LaneSelection>> {
    let mut out: BTreeMap<String, Vec<LaneSelection>> = BTreeMap::new();
    for root in LIVE_LAYER_ROOTS {
        for (binary, selections) in lane_test_filters(justfile, root) {
            out.entry(binary).or_default().extend(selections);
        }
    }
    out
}

/// The pure core of the coverage rule, so the counterfactual can be exercised on
/// synthetic input rather than by editing the real tree.
///
/// Returns one line per violation: a binary that can decline to assert, is not
/// selected by the lane, and is not declared as belonging somewhere else.
fn uncovered_capability_binaries(
    capability_conditional: &BTreeMap<String, Vec<String>>,
    lane_selected: &BTreeSet<String>,
    declared_elsewhere: &BTreeSet<String>,
) -> Vec<String> {
    capability_conditional
        .iter()
        .filter(|(name, _)| !lane_selected.contains(*name) && !declared_elsewhere.contains(*name))
        .map(|(name, signals)| format!("  {name} — declines to assert via {}", signals.join(", ")))
        .collect()
}

/// Every capability-conditional test binary must be REACHED by the containment lane,
/// or declared as belonging to another runner.
///
/// COUNTERFACTUAL: adding
/// `crates/worker/tests/sandbox_synthetic_live_probe.rs` — one test, one
/// `kata_test_utils::capability_skip` call, named by no recipe — makes this FAIL and
/// print `sandbox_synthetic_live_probe`. Deleting the file makes it pass again. The
/// synthetic file is deliberately NOT committed: the check must red for a binary
/// nobody thought about, which is not a property a committed fixture can demonstrate.
#[test]
fn every_capability_conditional_test_binary_rides_the_containment_lane() {
    let justfile = justfile_text();
    let binaries = workspace_test_binaries();
    let guard_file = this_guard_file();

    // NON-VACUITY, first, because every assertion below is satisfiable by finding
    // nothing. A tree scan that matched no directory and a justfile parse that found
    // no filter would both produce a serene green.
    assert!(
        binaries.len() > 50,
        "discovered only {} test binaries under crates/ and bin/ — the walker is not finding the \
         tree, and a coverage check over an empty set proves nothing",
        binaries.len()
    );
    assert!(
        binaries.values().any(|path| path == &guard_file),
        "this guard's own file ({}) is not among the {} discovered test binaries, so the \
         self-exclusion below would silently stop excluding anything. Derived from \
         CARGO_MANIFEST_DIR + file!(); one of them changed shape.",
        guard_file.display(),
        binaries.len()
    );

    let lane_selected = live_layer_binaries(&justfile);
    assert!(
        !lane_selected.is_empty(),
        "parsed ZERO `binary(...)` filters out of the `gate-containment` recipe graph. \
         Either the lane stopped selecting anything or the parse broke; both make this \
         check pass by observing nothing."
    );

    let capability_conditional: BTreeMap<String, Vec<String>> = binaries
        .iter()
        .filter(|(_, path)| *path != &guard_file)
        .filter_map(|(name, path)| {
            let source = binary_source(path).ok()?;
            let signals = capability_signals(&source);
            (!signals.is_empty()).then(|| (name.clone(), signals))
        })
        .collect();
    assert!(
        !capability_conditional.is_empty(),
        "found ZERO capability-conditional test binaries in a workspace whose containment \
         lane exists to run them. The marker set in LIVE_CAPABILITY_MARKERS has gone \
         stale, and this check is now vacuous."
    );

    // Evidence, not just a verdict: a lane that silently shrinks is the failure mode
    // here, so the numbers are printed on the PASSING path too.
    eprintln!(
        "CONTAINMENT-COVERAGE binaries={} capability-conditional={} lane-selected={} \
         declared-elsewhere={}",
        binaries.len(),
        capability_conditional.len(),
        lane_selected.len(),
        CAPABILITY_CONDITIONAL_OUTSIDE_THE_LANE.len(),
    );

    let declared_elsewhere: BTreeSet<String> = CAPABILITY_CONDITIONAL_OUTSIDE_THE_LANE
        .iter()
        .map(|(name, _)| (*name).to_string())
        .collect();

    let uncovered =
        uncovered_capability_binaries(&capability_conditional, &lane_selected, &declared_elsewhere);
    assert!(
        uncovered.is_empty(),
        "{} test binary/binaries can decline to assert for a HOST reason and are run by \
         NEITHER required lane — `just gate` reads their capability skip as a pass, and \
         `just gate-containment` does not select them, so both lanes go green having \
         measured nothing:\n{}\n\nFix one of two ways. Either add the binary to a \
         containment-lane recipe's `-E 'binary(...)'` filter (and make sure that \
         filter's `package(...)` clause names the binary's package — `binary(...)` is \
         exact and selects nothing otherwise), or add it to \
         CAPABILITY_CONDITIONAL_OUTSIDE_THE_LANE with the lane that owns it instead.",
        uncovered.len(),
        uncovered.join("\n"),
    );
}

/// Every allowlist row must still describe reality.
///
/// A row is stale in two directions and both are failures: the binary vanished
/// (rename, deletion) or the binary is now covered by the lane after all. Left alone,
/// such a row becomes a standing exemption for a name that no longer means what it
/// meant — the same drift the coverage check exists to stop, wearing the guard's own
/// clothes.
#[test]
fn the_containment_allowlist_carries_no_stale_rows() {
    let justfile = justfile_text();
    let binaries = workspace_test_binaries();
    let lane_selected = live_layer_binaries(&justfile);

    assert!(
        !CAPABILITY_CONDITIONAL_OUTSIDE_THE_LANE.is_empty(),
        "the allowlist is empty, so this check verifies nothing. If every \
         capability-conditional binary really did join the lane, delete this test with \
         the allowlist rather than leaving a check that passes by having no subject."
    );

    for (name, reason) in CAPABILITY_CONDITIONAL_OUTSIDE_THE_LANE {
        let path = binaries.get(*name).unwrap_or_else(|| {
            panic!(
                "the containment allowlist exempts `{name}`, which is not a test binary in \
                 this workspace any more. A stale exemption is worse than a missing one: it \
                 reads as a decision somebody made about code that exists."
            )
        });
        let source =
            binary_source(path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        assert!(
            !capability_signals(&source).is_empty(),
            "the allowlist exempts `{name}` from the containment lane, but it is no longer \
             capability-conditional at all — nothing about it needs exempting. Drop the row.\n\
             Its stated reason was: {reason}"
        );
        assert!(
            !lane_selected.contains(*name),
            "the allowlist exempts `{name}` from the containment lane, and the lane now \
             selects it anyway. One of the two is wrong; if the lane is right, drop the \
             row.\nIts stated reason was: {reason}"
        );
    }
}

/// Every `binary(...)` the containment lane names must EXIST.
///
/// A filter naming a binary that is not in the tree — a rename, a typo, a file moved
/// to another crate — matches nothing, and matching nothing is indistinguishable from
/// a clean run in the recipe's own output. This is the `#[kata_timeout]`-was-decorative
/// failure shape applied to a nextest filter, and the lane cannot see it.
#[test]
fn every_containment_filter_names_a_test_binary_that_exists() {
    let justfile = justfile_text();
    let binaries = workspace_test_binaries();
    let lane_selected = live_layer_binaries(&justfile);

    assert!(
        !lane_selected.is_empty(),
        "parsed ZERO `binary(...)` filters out of the `gate-containment` recipe graph"
    );

    let dangling: Vec<&String> = lane_selected
        .iter()
        .filter(|name| !binaries.contains_key(*name))
        .collect();
    assert!(
        dangling.is_empty(),
        "the containment lane selects `binary(...)` names with no test binary behind \
         them: {dangling:?}. nextest's `binary(...)` is EXACT, so such a filter selects \
         nothing and the recipe reports the same green it reports for a real run."
    );
}

/// The coverage rule REDS on a binary nobody covered, and GREENS the moment it is
/// covered — exercised on synthetic input so the counterfactual is part of the suite
/// rather than a check someone once ran by hand.
#[test]
fn the_coverage_rule_names_an_uncovered_binary_and_clears_when_it_is_covered() {
    let conditional: BTreeMap<String, Vec<String>> = [
        (
            "sandbox_synthetic_live_probe".to_string(),
            vec!["`SKIP[`".to_string()],
        ),
        (
            "oci_runtime_live".to_string(),
            vec!["`require_live(`".to_string()],
        ),
    ]
    .into_iter()
    .collect();
    let declared = BTreeSet::new();

    // RED: the lane selects the real binary and knows nothing of the new one.
    let selected: BTreeSet<String> = ["oci_runtime_live".to_string()].into_iter().collect();
    let violations = uncovered_capability_binaries(&conditional, &selected, &declared);
    assert_eq!(
        violations.len(),
        1,
        "expected exactly the uncovered binary to be reported, got: {violations:?}"
    );
    assert!(
        violations[0].contains("sandbox_synthetic_live_probe"),
        "the failure must NAME the binary, not just count it: {violations:?}"
    );

    // GREEN via the recipe filter.
    let selected: BTreeSet<String> = [
        "oci_runtime_live".to_string(),
        "sandbox_synthetic_live_probe".to_string(),
    ]
    .into_iter()
    .collect();
    assert!(
        uncovered_capability_binaries(&conditional, &selected, &declared).is_empty(),
        "adding the binary to a containment filter must clear the violation"
    );

    // GREEN via an explicit declaration — the only other permitted answer.
    let selected: BTreeSet<String> = ["oci_runtime_live".to_string()].into_iter().collect();
    let declared: BTreeSet<String> = ["sandbox_synthetic_live_probe".to_string()]
        .into_iter()
        .collect();
    assert!(
        uncovered_capability_binaries(&conditional, &selected, &declared).is_empty(),
        "declaring the binary's real owner must clear the violation"
    );
}

/// The classifier recognises a capability skip written EVERY way this workspace
/// writes one, and does not fire on a host-independent test.
///
/// The second half matters as much as the first: a marker set that matched everything
/// would make the coverage check demand the containment lane run the entire
/// workspace, and the pressure would be to delete the check rather than fix it.
#[test]
fn the_capability_classifier_recognises_each_spelling_and_no_more() {
    for (marker, why) in LIVE_CAPABILITY_MARKERS {
        let source = format!("fn t() {{ let _ = \"{marker}\"; }}\n");
        assert!(
            !capability_signals(&source).is_empty(),
            "marker `{marker}` ({why}) is in the table but the classifier does not fire on it"
        );
    }

    assert!(
        capability_signals("#[test]\nfn pure() { assert_eq!(1 + 1, 2); }\n").is_empty(),
        "a host-independent test must NOT be classified capability-conditional"
    );
    assert!(
        capability_signals("/// prose mentioning #[ignore] in a doc comment\n#[test]\nfn t() {}\n")
            .is_empty(),
        "`#[ignore]` discussed in PROSE is not an `#[ignore]` attribute; this workspace's \
         doc comments are full of the former"
    );
    assert!(
        !capability_signals("#[test]\n#[ignore = \"needs a kernel\"]\nfn t() {}\n").is_empty(),
        "a real `#[ignore]` attribute must be classified — it is the mechanism that keeps \
         a host-dependent test out of `just test` entirely"
    );
}

// ───────────────────────────────────────────────────────────────────────────────
// TEST-GRANULAR LANE COVERAGE — the blind spot INSIDE a lane-selected binary.
//
// Everything above derives coverage from `binary(...)` names. The lane does not
// select at that granularity: a step like `just smoke shell_` expands to
// `(binary(smokes) or binary(live_smoke)) and test(shell_)`. `reachable_recipes`
// throws the ARGUMENT away, so `selected_binaries` would report both binaries as
// lane-covered while the lane ran a handful of their `#[ignore]`d tests.
//
// That is a binary-granular guard pointed at a test-granular filter: without these
// checks, narrowing the lane's step to ONE test leaves every assertion in this file
// green.
//
// THE FILTER IS A SUBTRACTION, and these checks read it as one. `just smoke-no-budget`
// is `(binary(smokes) or binary(live_smoke)) and not
// test(smoke_workspace_ro_outputs)`,
// so the only way a gate's `-E` expression can leave a live smoke unrun is to name it in
// a negated `test(...)` clause: `not test(NAME)`, `!test(NAME)` or `not test(=NAME)`,
// each read here and held to its roster. Every other negation in a gate expression is
// refused by `every_gate_filter_negates_only_in_a_form_this_file_reads`, and so is every
// line of a gate recipe that names nextest in any form but the canonical run
// (`canonical_run`), which has no place for a libtest `--skip`, a positional name
// filter, or an option outside its list (`--exact`, `--partition`, `-p`). What a
// profile's `default-filter` and a `--run-ignored` mode leave out is not judged there.
// So a NEW `#[ignore]`d smoke is RUN by the required lane on the day it lands, and
// needs no roster row. What fails the gate is a new
// EXCLUSION — see `the_lane_excludes_exactly_the_model_budget_smokes`, which
// requires every subtracted name to be a real test with a stated budget reason.
// ───────────────────────────────────────────────────────────────────────────────

/// Every `just <recipe> <args...>` call reachable from `root`, ARGUMENTS KEPT.
///
/// [`reachable_recipes`] deliberately answers "which recipes run"; this answers
/// "with what", which is a different question and the one a `test(...)` filter
/// lives in. It uses the same command-position parsing and fail-closed dynamic-call
/// rules as [`reachable_recipes`].
fn reachable_invocations(justfile: &Justfile, root: &str) -> Vec<(String, Vec<String>)> {
    let mut pending = vec![root.to_owned()];
    let mut seen = BTreeSet::new();
    let mut invocations = Vec::new();

    while let Some(name) = pending.pop() {
        let name = resolved_recipe(justfile, &name).to_owned();
        if !seen.insert(name.clone()) {
            continue;
        }
        let recipe = justfile
            .recipes
            .get(&name)
            .unwrap_or_else(|| panic!("reachable just recipe `{name}` must exist"));
        for dependency in &recipe.dependencies {
            pending.push(dependency.recipe.clone());
            invocations.push((dependency.recipe.clone(), Vec::new()));
        }
        let body = recipe_body(justfile, &name)
            .unwrap_or_else(|| panic!("reachable just recipe `{name}` must exist"));
        for call in calls_in_body(&body, &name) {
            pending.push(call.recipe.clone());
            invocations.push((call.recipe, call.args));
        }
    }
    invocations
}

/// What ONE lane invocation's `-E` expression does to ONE test binary.
///
/// nextest's `test(...)` is a SUBSTRING match and its `not test(...)` is the same
/// match subtracted, so both halves are needed to answer "does the lane run this
/// test". Keeping them apart — rather than collapsing to a single "is it covered"
/// boolean — is what lets a failure say WHICH clause is responsible.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct LaneSelection {
    /// Positive `test(NAME)` narrowings. An EMPTY string means "no narrowing":
    /// every test in the binary is in scope before subtraction.
    include: BTreeSet<String>,
    /// Positive `test(=NAME)` narrowings — nextest's EXACT matcher, which is how an L2
    /// step names the cells it took from the push tier.
    include_exact: BTreeSet<String>,
    /// `not test(NAME)` / `!test(NAME)` subtractions, applied after `include`.
    exclude: BTreeSet<String>,
    /// `not test(=NAME)` subtractions — how an L1 step gives a cell to L2.
    exclude_exact: BTreeSet<String>,
}

impl LaneSelection {
    /// Does this one invocation run `test`? nextest semantics, not ours: an empty
    /// include means unnarrowed, a non-empty one matches by substring, and any
    /// matching exclusion wins.
    fn selects(&self, test: &str) -> bool {
        let included = self
            .include
            .iter()
            .any(|filter| filter.is_empty() || test.contains(filter.as_str()))
            || self.include_exact.iter().any(|name| names_test(name, test));
        let excluded = self
            .exclude
            .iter()
            .any(|filter| test.contains(filter.as_str()))
            || self.exclude_exact.iter().any(|name| names_test(name, test));
        included && !excluded
    }
}

/// Does the text BEFORE a `test(` negate it? nextest spells negation `not` or `!`, and
/// both are read: a reader that knew only one would drop the other's clause from its
/// model while nextest still applied it.
fn negates_clause(before: &str) -> bool {
    let before = before.trim_end();
    before.ends_with('!')
        || before.strip_suffix("not").is_some_and(|head| {
            !head
                .chars()
                .last()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        })
}

/// The `not test(NAME)` / `!test(NAME)` names subtracted by a recipe body — nextest's
/// default (substring) matcher, negated.
///
/// Literal names only. A `not test({{ <param> }})` would be a subtraction whose
/// subject depends on the caller, and admitting one here would let a lane exclude
/// a test by an argument this file cannot resolve — silence in the shape of a
/// filter, which is the failure this whole section exists to stop. Every negated form
/// this does not read — another matcher, a negated group or predicate — is refused in a
/// gate expression by `every_gate_filter_negates_only_in_a_form_this_file_reads`.
fn excluded_test_names(body: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut from = 0;
    while let Some(at) = body[from..].find("test(") {
        let start = from + at;
        from = start + "test(".len();
        let preceded_by_word = body[..start]
            .chars()
            .last()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
        if preceded_by_word || !negates_clause(&body[..start]) {
            continue;
        }
        if let Some(close) = body[from..].find(')') {
            let name = &body[from..from + close];
            if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                out.insert(name.to_string());
            }
        }
    }
    out
}

/// The `test(=NAME)` names a recipe body uses — nextest's EXACT matcher — either the
/// NEGATED ones (`not test(=NAME)` / `!test(=NAME)`: an L1 step giving a cell to L2) or
/// the positive ones (an L2 step, or an exact single-test route, naming what it runs).
///
/// Literal names only, as for [`excluded_test_names`]; a module path (`a::b::c`) is
/// kept whole.
fn exact_test_names(body: &str, negated: bool) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut from = 0;
    while let Some(at) = body[from..].find("test(=") {
        let start = from + at;
        let rest = &body[start + "test(=".len()..];
        from = start + "test(=".len();
        let Some(close) = rest.find(')') else {
            continue;
        };
        let name = &rest[..close];
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
        {
            continue;
        }
        if negates_clause(&body[..start]) == negated {
            out.insert(name.to_string());
        }
    }
    out
}

/// Does an exact filter `name` select the test named `test`? nextest matches the full
/// test path; the ignored-attribute scan yields bare fn names, so a module-qualified
/// filter matches its last segment.
fn names_test(name: &str, test: &str) -> bool {
    name == test || name.rsplit("::").next() == Some(test)
}

/// binary name -> every lane invocation that touches it, as a [`LaneSelection`].
///
/// A VEC, not a merged set: two invocations of the same binary are two runs, and
/// unioning their clauses would let one invocation's `not test(...)` cancel a
/// sibling invocation that actually runs the test. A test is run by the lane iff
/// SOME invocation selects it.
///
/// Derived from the recipe bodies, never transcribed. A recipe whose `-E`
/// expression narrows by `test({{ <param> }})` is resolved against the argument
/// the lane actually passes it; a recipe that names only `binary(...)` filters
/// contributes the empty (unnarrowed) include for each binary it names.
fn lane_test_filters(justfile: &Justfile, root: &str) -> BTreeMap<String, Vec<LaneSelection>> {
    let mut out: BTreeMap<String, Vec<LaneSelection>> = BTreeMap::new();
    for (recipe, args) in reachable_invocations(justfile, root) {
        // A recipe that RE-EXECS ITSELF to take a lock (`exec
        // scripts/installed-main-lock.sh just smoke <dynamic>`) forwards its
        // own parameter unresolved. That is the same invocation under another
        // process, not a second narrowing, and reading the interpolation as a filter
        // would put a literal that matches no test into the set.
        if args.iter().any(|arg| arg.contains(DYNAMIC)) {
            continue;
        }
        let Some(body) = recipe_body(justfile, &recipe) else {
            continue;
        };
        let mut binaries = BTreeSet::new();
        let mut rest = body.as_str();
        while let Some(at) = rest.find("binary(") {
            rest = &rest[at + "binary(".len()..];
            if let Some(close) = rest.find(')') {
                let name = &rest[..close];
                if !name.is_empty()
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                {
                    binaries.insert(name.to_string());
                }
            }
        }
        // `test(<dynamic>)` is the only shape in this justfile that narrows by test
        // NAME from a recipe parameter. A body without it cannot be narrowed by an
        // argument, so the filter is empty however the lane calls it.
        let narrows = body.contains(&format!("test({DYNAMIC}"));
        let filter = if narrows {
            args.first().cloned().unwrap_or_default()
        } else {
            String::new()
        };
        let exclude = excluded_test_names(&body);
        let include_exact = exact_test_names(&body, false);
        let exclude_exact = exact_test_names(&body, true);
        // A body that names its cells EXACTLY is narrowed to them; only a body with
        // neither kind of narrowing runs the whole binary.
        let include: BTreeSet<String> = if include_exact.is_empty() {
            [filter.clone()].into_iter().collect()
        } else {
            BTreeSet::new()
        };
        for binary in binaries {
            out.entry(binary).or_default().push(LaneSelection {
                include: include.clone(),
                include_exact: include_exact.clone(),
                exclude: exclude.clone(),
                exclude_exact: exclude_exact.clone(),
            });
        }
    }
    out
}

/// The `#[ignore]`d test function names in one test-binary source file.
///
/// Matched as an ATTRIBUTE at the start of a trimmed line (the same rule
/// [`capability_signals`] uses, and for the same reason: this workspace's doc
/// comments discuss `#[ignore]` constantly), then paired with the next `fn` name.
fn ignored_test_names(source: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut armed = false;
    for line in source.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#[ignore") {
            armed = true;
            continue;
        }
        if !armed {
            continue;
        }
        let after_async = trimmed.strip_prefix("async ").unwrap_or(trimmed);
        if let Some(rest) = after_async.strip_prefix("fn ") {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                names.push(name);
                armed = false;
            }
        }
    }
    names
}

/// `#[ignore]`d tests inside a lane-selected binary that the lane's own filter
/// does NOT reach, and which no allowlist row claims.
///
/// Split out as a pure function so the counterfactual runs on synthetic input
/// rather than by editing the real justfile.
fn unrun_ignored_tests(
    ignored: &BTreeMap<String, Vec<String>>,
    filters: &BTreeMap<String, Vec<LaneSelection>>,
    declared: &BTreeSet<String>,
) -> Vec<String> {
    let mut out = Vec::new();
    for (binary, tests) in ignored {
        let Some(selections) = filters.get(binary) else {
            continue;
        };
        for test in tests {
            // NOT short-circuited on "some invocation is unnarrowed": the lane's include
            // IS unnarrowed and the subtraction is the whole filter, so that shortcut
            // would skip every binary the lane runs and report a clean sheet over the
            // two smokes it deliberately does not.
            let selected = selections
                .iter()
                .any(|selection| selection.selects(test.as_str()));
            if !selected && !declared.contains(test) {
                out.push(format!("  {binary}::{test}"));
            }
        }
    }
    out
}

/// `#[ignore]`d tests inside a binary the containment lane SELECTS but whose
/// filter does not REACH — each with the reason it is not run.
///
/// The lane's step is `just smoke-no-budget`, which runs every no-budget live smoke, so
/// the roster holds only what that step subtracts. A quarantine that outlives its
/// entries reports debt nobody owes, so the rows are DERIVED — with the roster empty,
/// the check prints exactly this name:
///
/// ```text
/// 1 `#[ignore]`d test(s) live in a binary the containment lane SELECTS but which
/// its test-name filter does not REACH, and no row claims them:
///   smokes::smoke_workspace_ro_outputs
/// ```
///
/// It is here for ONE reason and it is not flakiness: it drives a real
/// `nanocode_openai` turn, so it spends real model budget and is run by hand.
/// `the_lane_excludes_exactly_the_model_budget_smokes` holds that
/// meaning to the wording, so a row added for any other reason must say so out loud.
///
/// A NEW `#[ignore]`d smoke needs no row: the lane's include is unnarrowed, so it
/// RUNS on the day it lands. What needs a row — and fails `just gate` without
/// one — is a new `not test(...)` clause in
/// `just smoke-no-budget`.
const IGNORED_TESTS_OUTSIDE_THE_LANE: &[(&str, &str)] = &[(
    "smoke_workspace_ro_outputs",
    "drives `workflows/smoke/sandbox-smoke-workspace-ro.star`, whose stage runs a real \
         `nanocode_openai` turn on the host's `kata login openai` — real model spend, so it \
         is run by hand: `just smoke smoke_workspace_ro_outputs`.",
)];

/// The words a roster row must use to claim the model-budget exemption.
///
/// Two readers disagreeing about what a word means is a defect class of its own, and
/// "excluded" is exactly that word: an exclusion for cost and an exclusion for
/// flakiness look identical in a filter and could not be more different in what
/// they license. A row that cannot say `budget` or `spend` is not claiming the
/// exemption, whatever else it says.
const MODEL_BUDGET_WORDS: &[&str] = &["budget", "spend"];

/// Every containment proof must pass `--run-ignored`, PER RECIPE.
///
/// THE DEFECT THIS PINS. `the_containment_lane_runs_ignored_tests_and_the_gate_still_does_not`
/// concatenates every reachable lane body into ONE string and asserts that string
/// contains `--run-ignored`. Four recipes satisfied it, so the fifth
/// (the deleted `sandbox-fresh-host-sims`) could omit the flag and no check saw it: its two
/// binaries assert only under `KATA_SANDBOX_REQUIRE_LIVE`, so under `just test`
/// they already skip-as-pass, and an `#[ignore]` on one of their cells would have
/// removed its last executing site with both required gates green.
///
/// COUNTERFACTUAL: drop `--run-ignored all` from any lane `cargo nextest run` line
/// and this names the recipe and the line.
#[test]
fn every_containment_proof_runs_ignored_tests() {
    let justfile = justfile_text();
    let reachable = reachable_recipes(&justfile, "gate-containment");

    let mut checked = 0usize;
    let mut missing = Vec::new();
    for (recipe, body) in &reachable {
        // Fold shell line continuations first: the flag legitimately sits on a
        // later physical line of the same command.
        let folded = body.replace("\\\n", " ");
        for line in folded.lines() {
            let line = line.trim();
            if line.starts_with('#') || !line.contains("cargo nextest run") {
                continue;
            }
            checked += 1;
            if !line.contains("--run-ignored") {
                missing.push(format!("  {recipe}: {line}"));
            }
        }
    }

    assert!(
        checked >= 5,
        "found only {checked} `cargo nextest run` lines in the containment lane graph — \
         the scan is not reading the recipes, and a per-line check over nothing proves \
         nothing"
    );
    assert!(
        missing.is_empty(),
        "{} containment-lane nextest invocation(s) do not pass `--run-ignored`:\n{}\n\n\
         `#[ignore]` is how this workspace keeps a host-dependent test out of `just \
         test`, so a proof that does not pass the flag cannot reach one — and the union \
         assertion in `the_containment_lane_runs_ignored_tests_and_the_gate_still_does_not` \
         stays green because its SIBLINGS carry the flag.",
        missing.len(),
        missing.join("\n"),
    );
}

/// The `--run-ignored` mode one nextest command line passes: `default` when absent.
fn run_ignored_mode(line: &str) -> &str {
    let words: Vec<&str> = line.split_whitespace().collect();
    words
        .iter()
        .position(|word| *word == "--run-ignored")
        .and_then(|at| words.get(at + 1).copied())
        .or_else(|| {
            words
                .iter()
                .find_map(|word| word.strip_prefix("--run-ignored="))
        })
        .unwrap_or("default")
}

/// What ONE nextest command line's `-E` expression does to the binaries it names: the
/// [`LaneSelection`] of its literal `test(=NAME)`, `not test(=NAME)`, `not test(NAME)`
/// (or `!test(NAME)`) and positive `test(NAME)` clauses. With no positive name clause the include is
/// unnarrowed.
fn line_selection(line: &str) -> LaneSelection {
    let mut include = BTreeSet::new();
    let mut from = 0;
    while let Some(at) = line[from..].find("test(") {
        let start = from + at;
        from = start + "test(".len();
        let rest = &line[from..];
        if rest.starts_with('=') {
            continue;
        }
        if negates_clause(&line[..start]) {
            continue;
        }
        if let Some(close) = rest.find(')') {
            include.insert(rest[..close].to_owned());
        }
    }
    let include_exact = exact_test_names(line, false);
    if include.is_empty() && include_exact.is_empty() {
        include.insert(String::new());
    }
    LaneSelection {
        include,
        include_exact,
        exclude: excluded_test_names(line),
        exclude_exact: exact_test_names(line, true),
    }
}

/// The roots whose recipes [`read_gates`] judges: both L1 tiers and L2.
const GATE_ROOTS: &[&str] = &["gate", "gate-push", "gate-nightly"];

/// The assignments a canonical run may put before `cargo`.
const CANONICAL_ENVIRONMENT: &[&str] = &["KATA_LIVE_SMOKE=1", "KATA_SANDBOX_REQUIRE_LIVE=1"];

/// The names a canonical run may unset with `env -u`: the publication-fault knobs and
/// the E3 selectors that would make a run spend. Never a knob a live run needs.
const CANONICAL_UNSET: &[&str] = &[
    "KATA_TEST_PUBLICATION_FAULT_MODE",
    "KATA_TEST_PUBLICATION_FAULT_ROOT",
    "KATA_E3_AGENT",
    "KATA_E3_FUNDED",
    "KATA_E3_FORGE_CLONE",
];

/// The one canonical run that builds and runs nothing: `test-build`'s.
const BUILD_ONLY: [&str; 5] = ["cargo", "nextest", "run", "--workspace", "--no-run"];

/// The options a canonical run may pass that take no further word.
const CANONICAL_FLAGS: &[&str] = &["--workspace", "--test-threads=1"];

/// The options a canonical run may pass with a value as the next word, and each one's
/// allowed values.
const CANONICAL_VALUES: &[(&str, &[&str])] = &[
    ("-P", &["live-smoke", "measurement", "soak"]),
    ("--test-threads", &["1"]),
    ("--run-ignored", &["all", "ignored-only", "only"]),
    ("--success-output", &["final", "immediate"]),
];

/// The characters with which the shell continues, rewrites or redirects a word: a
/// quote, an escape, an expansion, a brace or pathname pattern (`(` for an extended
/// one), a redirection — and Just's own interpolation.
const SHELL_ACTIVE: &[char] = &[
    '\'', '"', '\\', '$', '`', '{', '*', '?', '[', '(', '<', '>', DYNAMIC,
];

/// One logical line of a recipe body.
struct BodyLine {
    /// The 1-based number, in the body, of its first physical line.
    number: usize,
    /// Its text, its physical lines joined ([`body_lines`]).
    text: String,
}

/// A recipe body's logical lines.
///
/// A LINEWISE recipe's lines are joined as Just joins them before it hands each to the
/// shell (observed with Just 1.59.0): a physical line ending in `\` — one or any run of
/// them — loses that one `\` and is joined to the next, whose leading spaces and tabs
/// are removed; a `\` on the body's last line is dropped. So `: \\` joins the next
/// line onto a `:` command, and `cargo nex\` over an indented `test run` runs `cargo
/// nextest run`.
///
/// A SCRIPT recipe's body (its first line `#!`) is its shell's, so a physical line is
/// joined to the next only when it ends in an odd run of `\`, and nothing is removed but
/// that `\` and the newline; a continuation the body ends on keeps its `\`. No shell is
/// parsed either way, so a line the shell would not join (a comment, a quoted
/// here-document's) is joined too, which only widens what one line is judged to hold.
fn body_lines(body: &str) -> Vec<BodyLine> {
    let script = body.starts_with("#!");
    let mut lines = Vec::new();
    let mut open: Option<BodyLine> = None;
    for (index, physical) in body.lines().enumerate() {
        let physical = match &open {
            Some(_) if !script => physical.trim_start_matches([' ', '\t']),
            _ => physical,
        };
        let backslashes = physical.len() - physical.trim_end_matches('\\').len();
        let continues = if script {
            backslashes % 2 == 1
        } else {
            backslashes > 0
        };
        let part = if continues {
            &physical[..physical.len() - 1]
        } else {
            physical
        };
        open.get_or_insert_with(|| BodyLine {
            number: index + 1,
            text: String::new(),
        })
        .text
        .push_str(part);
        if !continues {
            lines.extend(open.take());
        }
    }
    if let Some(mut dangling) = open {
        if script {
            dangling.text.push('\\');
        }
        lines.push(dangling);
    }
    lines
}

/// `text` with the two texts this reader does not judge each replaced by a space:
/// `target/nextest/` (the directory nextest writes its reports under) and
/// `pgrep -x 'NAME'`, NAME being any run of letters, digits, `_` and `-` (a process-name
/// lookup).
fn judged_text(text: &str) -> String {
    const LOOKUP: &str = "pgrep -x '";
    let text = text.replace("target/nextest/", " ");
    let mut out = String::new();
    let mut rest = text.as_str();
    while let Some(at) = rest.find(LOOKUP) {
        let name = &rest[at + LOOKUP.len()..];
        let length = name
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
            .unwrap_or(name.len());
        if name[length..].starts_with('\'') {
            out.push_str(&rest[..at]);
            out.push(' ');
            rest = &name[length + 1..];
        } else {
            out.push_str(&rest[..at + LOOKUP.len()]);
            rest = name;
        }
    }
    out.push_str(rest);
    out
}

/// One canonical nextest run.
#[derive(Clone, Debug, Eq, PartialEq)]
struct NextestRun {
    /// `cargo nextest run` and its options, the `-E` value without its quotes, joined by
    /// single spaces: what the text readers here ([`run_ignored_mode`],
    /// [`line_selection`]) read.
    text: String,
    /// The `-E` value.
    filter: Option<String>,
}

/// One word of a line read as a canonical run.
enum CanonicalWord {
    /// A run of anything but blanks that does not begin `'`.
    Plain(String),
    /// The text between a `'` that begins a word and the next `'`.
    Quoted(String),
}

/// The blank-separated words of `text`, or why it cannot be split into them: a quoted
/// word that is left open or runs on into more text. A plain word is taken as written —
/// [`canonical_run`] matches each one whole against a fixed word, so a quote, an escape
/// or an expansion in one matches nothing.
fn canonical_words(text: &str) -> Result<Vec<CanonicalWord>, String> {
    const BLANK: [char; 2] = [' ', '\t'];
    let mut words = Vec::new();
    let mut rest = text.trim_start_matches(BLANK);
    while !rest.is_empty() {
        if let Some(quoted) = rest.strip_prefix('\'') {
            let Some((text, after)) = quoted.split_once('\'') else {
                return Err("a single-quoted word that does not close".into());
            };
            if !(after.is_empty() || after.starts_with(BLANK)) {
                return Err("a quoted word joined to more text".into());
            }
            words.push(CanonicalWord::Quoted(text.to_owned()));
            rest = after;
        } else {
            let end = rest.find(BLANK).unwrap_or(rest.len());
            words.push(CanonicalWord::Plain(rest[..end].to_owned()));
            rest = &rest[end..];
        }
        rest = rest.trim_start_matches(BLANK);
    }
    Ok(words)
}

/// The canonical run `line` is, or why it is not one.
///
/// THE CANONICAL FORM — the one way a gate recipe may write a nextest run — is one
/// logical line ([`body_lines`]) holding only these words, separated by spaces and
/// tabs, indentation allowed:
///
/// ```text
/// PREFIX   any of KATA_LIVE_SMOKE=1, KATA_SANDBOX_REQUIRE_LIVE=1
///          (CANONICAL_ENVIRONMENT), or  env -u NAME [-u NAME]…  with each NAME
///          one of CANONICAL_UNSET
/// COMMAND  cargo nextest run
/// OPTIONS  each at most once, in any order:
///          --workspace   --test-threads=1   --test-threads 1
///          -P live-smoke|measurement|soak
///          --run-ignored all|ignored-only|only
///          --success-output final|immediate
///          -E 'FILTER'
/// ```
///
/// or, exactly, `cargo nextest run --workspace --no-run` ([`BUILD_ONLY`]). FILTER
/// stands between two `'` and holds no `'`, so the shell passes it to nextest as
/// written (an empty one, and a Just interpolation in one, are [`unread_negations`]'s
/// to refuse). Every other word is matched whole against one of the words above, each
/// of them letters, digits, `_`, `=` and `-`, so nothing else on the line is quoted,
/// escaped, expanded, redirected, commented or interpolated, no second command shares
/// it, and nothing follows the options: no `--`, so no libtest argument (`--skip`), no
/// positional name filter, and no other nextest option (`--no-run` on any other run,
/// `--exact`, `--partition`, `-p`, `--ignore-default-filter`, `--filterset`, an
/// attached `-EFILTER`).
fn canonical_run(line: &BodyLine) -> Result<NextestRun, String> {
    let words = canonical_words(&line.text)?;
    let plain = |at: usize| match words.get(at) {
        Some(CanonicalWord::Plain(text)) => Some(text.as_str()),
        _ => None,
    };
    if words.len() == BUILD_ONLY.len()
        && (0..BUILD_ONLY.len()).all(|at| plain(at) == Some(BUILD_ONLY[at]))
    {
        return Ok(NextestRun {
            text: BUILD_ONLY.join(" "),
            filter: None,
        });
    }
    let mut at = 0;
    if plain(at) == Some("env") {
        at += 1;
        while plain(at) == Some("-u") {
            if !plain(at + 1).is_some_and(|name| CANONICAL_UNSET.contains(&name)) {
                return Err(format!("`env -u` without one of {CANONICAL_UNSET:?}"));
            }
            at += 2;
        }
        if at == 1 {
            return Err("`env` without a `-u NAME`".into());
        }
    } else {
        while plain(at).is_some_and(|word| CANONICAL_ENVIRONMENT.contains(&word)) {
            at += 1;
        }
    }
    if [plain(at), plain(at + 1), plain(at + 2)] != [Some("cargo"), Some("nextest"), Some("run")] {
        return Err(format!(
            "it does not read `cargo nextest run` after `env -u NAME…` or any of \
             {CANONICAL_ENVIRONMENT:?}"
        ));
    }
    at += 3;
    let mut text = vec!["cargo nextest run".to_owned()];
    let mut filter = None;
    let mut seen = BTreeSet::new();
    while at < words.len() {
        let Some(option) = plain(at) else {
            return Err("a quoted word that is not an `-E` value".into());
        };
        at += 1;
        if !seen.insert(option.split('=').next().unwrap_or_default()) {
            return Err(format!("`{option}` given twice"));
        }
        text.push(option.to_owned());
        if CANONICAL_FLAGS.contains(&option) {
            continue;
        }
        if option == "-E" {
            let Some(CanonicalWord::Quoted(value)) = words.get(at) else {
                return Err("`-E` without a single-quoted value as its next word".into());
            };
            at += 1;
            text.push(value.clone());
            filter = Some(value.clone());
            continue;
        }
        let Some((_, values)) = CANONICAL_VALUES.iter().find(|(name, _)| *name == option) else {
            return Err(format!("`{option}` is not an option of the canonical form"));
        };
        match plain(at).filter(|value| values.contains(value)) {
            Some(value) => text.push(value.to_owned()),
            None => {
                return Err(format!(
                    "`{option}` without one of {values:?} as its next word"
                ));
            }
        }
        at += 1;
    }
    Ok(NextestRun {
        text: text.join(" "),
        filter,
    })
}

/// Each `cargo` on `text` whose subcommand the shell, or Just, could decide: a
/// subcommand not written as a plain word can become `nextest` at run time, and a cargo
/// option before it can define an alias (`--config`).
///
/// JUDGED: every `cargo` that does not directly follow a letter, a digit, `_` or `.`
/// (so not `.cargo/`). The `'`, `"`, `}` and `)` directly after it are passed over —
/// each can close a quoted or substituted `cargo` — and then:
///
/// * a blank: the NEXT WORD is judged, or, when that begins `+` (a toolchain), it and
///   the word after it. REFUSED: a word beginning `-`, and a word that — its final `'`
///   and `"` aside, which close a quote or open one that takes in the blank after it —
///   holds any [`SHELL_ACTIVE`] character (in a toolchain, any but a Just
///   interpolation);
/// * anything else: REFUSED when the text up to the next blank holds a [`SHELL_ACTIVE`]
///   character (`cargo$x`, `cargo\`, `cargo>log`, `cargo-nex""test`), otherwise not
///   judged — a longer name or the end of the command (`cargo-deny`, `cargo;`).
///
/// A backquote is never passed over: an empty substitution joins the words around it
/// (`` nex` `test ``) or vanishes (`` cargo` ` ``).
fn undecided_cargo_subcommands(text: &str) -> Vec<String> {
    let active = |word: &str, toolchain: bool| {
        word.trim_end_matches(['\'', '"'])
            .contains(|c: char| SHELL_ACTIVE.contains(&c) && !(toolchain && c == DYNAMIC))
    };
    let mut out = Vec::new();
    for (at, _) in text.match_indices("cargo") {
        if text[..at]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        {
            continue;
        }
        let after = text[at + "cargo".len()..].trim_start_matches(['\'', '"', '}', ')']);
        let Some(next) = after.chars().next() else {
            continue;
        };
        if next != ' ' && next != '\t' {
            let glued = after.split([' ', '\t']).next().unwrap_or_default();
            if active(glued, false) {
                out.push(format!(
                    "`cargo{glued}`: the shell continues the word `cargo`"
                ));
            }
            continue;
        }
        let mut words = after.split([' ', '\t']).filter(|word| !word.is_empty());
        let Some(mut word) = words.next() else {
            continue;
        };
        if word.starts_with('+') {
            if active(word, true) {
                out.push(format!("`cargo {word}`: a toolchain the shell decides"));
                continue;
            }
            match words.next() {
                Some(subcommand) => word = subcommand,
                None => continue,
            }
        }
        if word.starts_with('-') {
            out.push(format!(
                "`cargo {word}`: a cargo option before the subcommand"
            ));
        } else if active(word, false) {
            out.push(format!(
                "`cargo {word}`: a subcommand that is not a plain word"
            ));
        }
    }
    out
}

/// What the gate checks read from one recipe body: its canonical runs, every refusal,
/// each naming the body line and why, and whether any line names nextest.
struct GateNextest {
    runs: Vec<NextestRun>,
    refusals: Vec<String>,
    names_nextest: bool,
}

/// Read one recipe body as TEXT, one logical line ([`body_lines`]) at a time. No shell is
/// parsed: a comment, a quoted string, a here-document's body and a script in another
/// language are judged like any other line.
///
/// A body NAMES NEXTEST when a line holds `nextest`, in any letter case and
/// [`judged_text`]'s two texts aside. REFUSED:
///
/// * in a body that names nextest, every line that is not blank and not exactly one
///   canonical run ([`canonical_run`]) — whether it names the word or not. So a body
///   that holds a run holds nothing else: no `#!` line (a script recipe), no lock
///   re-execution, no assignment, no condition, no other command, no comment;
/// * in any other body, each `cargo` [`undecided_cargo_subcommands`] names;
/// * in a canonical run's `-E` value, each negation [`unread_negations`] names.
///
/// NOT REFUSED: a body that never writes the word and assembles it at run time, wherever
/// [`undecided_cargo_subcommands`] does not refuse it: through a command word the shell
/// builds (`c""argo`, `"$c" nex""test`, `$c $s run`, `"${argv[@]}"`), a string it runs
/// or a program joins (`bash <<< "$line"`, `printf '%s' 'cargo nex' 'test run' | sh`),
/// a program handed a bare `cargo` (`… | xargs cargo`), or the environment, a file or a
/// command's output. What a script or program the recipe runs does itself is not read
/// either, and whether cargo is found behind a canonical line's `cargo` (an alias or a
/// function of that name, `hash -p`, `PATH`) is not judged.
fn read_gate_nextest(body: &str) -> GateNextest {
    let lines = body_lines(body);
    let judged: Vec<String> = lines.iter().map(|line| judged_text(&line.text)).collect();
    let names_nextest = judged
        .iter()
        .any(|text| text.to_ascii_lowercase().contains("nextest"));
    let mut read = GateNextest {
        runs: Vec::new(),
        refusals: Vec::new(),
        names_nextest,
    };
    for (line, judged) in lines.iter().zip(&judged) {
        let mut refuse = |why: String| {
            read.refusals.push(format!(
                "body line {}: {why}\n      {}",
                line.number,
                line.text.trim()
            ));
        };
        if !names_nextest {
            for undecided in undecided_cargo_subcommands(judged) {
                refuse(undecided);
            }
            continue;
        }
        if line.text.trim().is_empty() {
            continue;
        }
        match canonical_run(line) {
            Err(why) => refuse(format!(
                "the body names nextest, and this line is not a canonical run: {why}"
            )),
            Ok(run) => {
                for reason in run
                    .filter
                    .iter()
                    .flat_map(|filter| unread_negations(filter))
                {
                    refuse(reason);
                }
                read.runs.push(run);
            }
        }
    }
    read
}

/// Each place OUTSIDE the literal text of a recipe body where the justfile writes
/// `nextest`, in any letter case, into text a gate recipe runs, interpolates or runs
/// under: any variable assignment (its name and its expression), any setting the dump
/// reports, and, for each of `recipes`, a parameter (its name — an exported one is an
/// environment variable — and its default), a dependency argument, an attribute
/// (`[env(…)]`, `[script(…)]`) and an interpolation in its body, which
/// [`read_gate_nextest`] sees only as [`DYNAMIC`]. Each is read as the JSON `just
/// --dump` prints, so a string Just only builds (`"nex" + "test"`, `read(…)`,
/// `env(…)`) is not seen, nor is what that JSON leaves out: the `script-interpreter`
/// setting and an `unexport`.
fn nextest_outside_body_text(justfile: &Justfile, recipes: &BTreeSet<String>) -> Vec<String> {
    let names =
        |value: &serde_json::Value| value.to_string().to_ascii_lowercase().contains("nextest");
    let mut out = Vec::new();
    for (name, assignment) in &justfile.assignments {
        if names(assignment) {
            out.push(format!("the variable `{name}` names nextest"));
        }
    }
    if names(&justfile.settings) {
        out.push("a `set` setting names nextest".to_owned());
    }
    for name in recipes {
        let Some(recipe) = justfile.recipes.get(name) else {
            continue;
        };
        for parameter in &recipe.parameters {
            if parameter.name.to_ascii_lowercase().contains("nextest") || names(&parameter.default)
            {
                out.push(format!(
                    "`{name}`: the parameter `{}` names nextest",
                    parameter.name
                ));
            }
        }
        if recipe
            .dependencies
            .iter()
            .any(|dependency| names(&dependency.arguments))
        {
            out.push(format!("`{name}`: a dependency argument names nextest"));
        }
        if recipe.attributes.iter().any(names) {
            out.push(format!("`{name}`: an attribute names nextest"));
        }
        for (index, line) in recipe.body.iter().enumerate() {
            if line
                .iter()
                .any(|fragment| !fragment.is_string() && names(fragment))
            {
                out.push(format!(
                    "`{name}`, body line {}: an interpolation names nextest",
                    index + 1
                ));
            }
        }
    }
    out
}

/// What [`read_gates`] reads across every recipe reachable from its roots.
struct GateRead {
    /// Each reachable recipe's canonical runs, with the recipe's name.
    runs: Vec<(String, NextestRun)>,
    refusals: BTreeSet<String>,
}

/// Every recipe reachable from `roots`, read by [`read_gate_nextest`], and the justfile
/// outside the text of their bodies, read by [`nextest_outside_body_text`]. Also
/// REFUSED: a recipe whose body names nextest and that takes a parameter or carries an
/// attribute (`[script]`, `[env]`, `[private]`, any). So a run stands alone in a
/// linewise recipe — a script recipe's `#!` line is [`read_gate_nextest`]'s to refuse —
/// and a lock, a temporary directory or an exit status is the work of a recipe that
/// calls it by `just NAME`.
fn read_gates(justfile: &Justfile, roots: &[&str]) -> GateRead {
    let mut read = GateRead {
        runs: Vec::new(),
        refusals: BTreeSet::new(),
    };
    let mut recipes = BTreeSet::new();
    for root in roots {
        for (recipe, body) in reachable_recipes(justfile, root) {
            if !recipes.insert(recipe.clone()) {
                continue;
            }
            let gate = read_gate_nextest(&body);
            let header = &justfile.recipes[&recipe];
            if gate.names_nextest && !(header.parameters.is_empty() && header.attributes.is_empty())
            {
                read.refusals.insert(format!(
                    "  `{recipe}`: its body names nextest, so it takes no parameter and \
                     carries no attribute"
                ));
            }
            read.runs
                .extend(gate.runs.into_iter().map(|run| (recipe.clone(), run)));
            read.refusals.extend(
                gate.refusals
                    .into_iter()
                    .map(|refusal| format!("  `{recipe}`, {refusal}")),
            );
        }
    }
    read.refusals.extend(
        nextest_outside_body_text(justfile, &recipes)
            .into_iter()
            .map(|refusal| format!("  {refusal}")),
    );
    read
}

/// Each way `expression` negates that this file's readers ([`excluded_test_names`],
/// [`exact_test_names`], [`line_selection`] and the `binary(...)` scan) do not model.
/// Empty when every negation is `not` or `!` applied directly to ONE `test(...)`
/// predicate whose argument is a literal name.
///
/// REFUSED SET: an expression the shared [`parse_filterset`] refuses (a regex `/…/` or
/// glob `#…` matcher, a glob in another predicate, an unknown predicate, unbalanced
/// syntax); an expression built by Just interpolation; a negation of anything but one
/// bare `test(...)` predicate (a parenthesised group, even `not (test(NAME))`;
/// `binary(...)`; `package(...)`; a double negation), read from the tokens by
/// [`negations_not_of_one_test_predicate`];
/// the `-` set difference; `none()`; and a `test(...)` whose argument is not
/// `NAME` or `=NAME` (`~NAME`, `/re/`, `#glob`, a name with other characters).
/// Positive structure (which binaries an inclusion pairs with) is not judged here.
fn unread_negations(expression: &str) -> Vec<String> {
    if expression.contains(DYNAMIC) {
        return vec!["it is built by Just interpolation, which no reader here resolves".into()];
    }
    let parsed = match parse_filterset(expression) {
        Ok(parsed) => parsed,
        Err(error) => return vec![error],
    };
    // The negations, from the TOKENS: the tree has lost the parentheses that hide a
    // negated `not (test(x))` from every text reader here.
    let mut out = match negations_not_of_one_test_predicate(expression) {
        Ok(reasons) => reasons,
        Err(error) => return vec![error],
    };
    fn walk(filter: &Filterset, out: &mut Vec<String>) {
        match filter {
            Filterset::Not(inner) => walk(inner, out),
            Filterset::And(left, right) | Filterset::Or(left, right) => {
                walk(left, out);
                walk(right, out);
            }
            Filterset::None => out.push("it uses `none()`".into()),
            _ => {}
        }
    }
    walk(&parsed, &mut out);
    // The text outside every `predicate(...)` argument: the operators.
    let mut operators = String::new();
    let mut depth_in_argument = false;
    let mut previous_word = String::new();
    for ch in expression.chars() {
        if depth_in_argument {
            depth_in_argument = ch != ')';
            continue;
        }
        if ch == '(' && !previous_word.is_empty() {
            depth_in_argument = true;
            previous_word.clear();
            continue;
        }
        if ch.is_ascii_alphanumeric() || ch == '_' {
            previous_word.push(ch);
        } else {
            previous_word.clear();
        }
        operators.push(ch);
    }
    if operators.contains('-') {
        out.push("it uses `-` (set difference), a negation no reader here reads".into());
    }
    let mut from = 0;
    while let Some(at) = expression[from..].find("test(") {
        let start = from + at;
        from = start + "test(".len();
        if expression[..start]
            .chars()
            .last()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            continue;
        }
        let argument = expression[from..]
            .split(')')
            .next()
            .unwrap_or_default()
            .trim();
        let literal = match argument.strip_prefix('=') {
            Some(exact) => {
                !exact.is_empty()
                    && exact
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
            }
            None => {
                !argument.is_empty()
                    && argument
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_')
            }
        };
        if !literal {
            out.push(format!(
                "`test({argument})` is not a literal `NAME` or `=NAME`"
            ));
        }
    }
    out
}

/// Every nextest run a gate recipe writes is read, and no cell it subtracts is unclaimed.
///
/// THE DEFECT THIS PINS: a cell could leave a gate with every check here green — by a
/// negation the text readers do not model (`!test(NAME)` once, `not test(/re/)`, a
/// negated group, even `not (test(NAME))`), by a libtest `--skip NAME`, or by a nextest
/// run the reader did not find: quoted (`'--skip'`), after `&&`, in a subshell or a
/// substitution, in an `eval`, `sh -c` or here-string string, or built from a shell
/// variable the shell later overwrote. A reader that parses the shell is only as
/// complete as its parser, so none is parsed here: a gate recipe that writes `nextest`
/// holds only canonical runs ([`canonical_run`]), whose every word is fixed or one
/// single-quoted literal, in a linewise recipe of its own.
///
/// REFUSED, in every recipe reachable from `gate`, `gate-push` or `gate-nightly`
/// ([`read_gates`]): each line and each negation [`read_gate_nextest`] refuses; each
/// recipe [`read_gates`] refuses for its header; each place
/// [`nextest_outside_body_text`] names; a `not test(NAME)` / `!test(NAME)`
/// name that `IGNORED_TESTS_OUTSIDE_THE_LANE` does not claim; and a `not test(=NAME)`
/// name no `NIGHTLY_CELLS` row claims. What is NOT refused is [`read_gate_nextest`]'s
/// and [`nextest_outside_body_text`]'s to say.
#[test]
fn every_gate_filter_negates_only_in_a_form_this_file_reads() {
    let justfile = justfile_text();
    let gates = read_gates(&justfile, GATE_ROOTS);
    let filters: Vec<&String> = gates
        .runs
        .iter()
        .filter_map(|(_, run)| run.filter.as_ref())
        .collect();
    assert!(
        filters.len() >= 10,
        "NON-VACUITY: only {} filter expressions read across {GATE_ROOTS:?}",
        filters.len()
    );
    assert!(
        gates.refusals.is_empty(),
        "{} place(s) where a gate recipe names nextest, or runs cargo, in a form this file \
         does not read, so a cell it takes out of a gate is invisible to every roster \
         here:\n{}\n\nWrite a gate's nextest run in the canonical form (`canonical_run`): \
         one line, `cargo nextest run` after an allowed environment prefix, allowed \
         options only, the filter as one single-quoted `-E` value, nothing after it; \
         spell a subtraction `not test(NAME)` / `!test(NAME)` (a model-budget smoke, \
         `IGNORED_TESTS_OUTSIDE_THE_LANE`) or `not test(=NAME)` (a cell handed to L2, \
         `NIGHTLY_CELLS`). Put it in a linewise recipe that holds nothing else, no \
         parameter and no attribute, and call that recipe by `just NAME` from the one \
         that takes a lock or reads its exit status; put a note that names nextest \
         above the recipe.",
        gates.refusals.len(),
        gates
            .refusals
            .iter()
            .map(|refusal| refusal.replace(DYNAMIC, "{{…}}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    // One recipe of each tier, by name: a root lost from `GATE_ROOTS` would leave its
    // tier's runs unread, and the count above would not notice.
    for recipe in ["_test-run", "_smoke-no-budget-run", "_nightly-oci-live-run"] {
        assert!(
            gates.runs.iter().any(|(name, _)| name == recipe),
            "NON-VACUITY: no run read from `{recipe}`; is its tier still among {GATE_ROOTS:?}?"
        );
    }
    // The forms read, held to their rosters across EVERY gate root — not only the
    // containment lane and the push tier the roster checks above read.
    let mut subtracted = BTreeSet::new();
    let mut subtracted_exact = BTreeSet::new();
    for filter in filters {
        subtracted.extend(excluded_test_names(filter));
        subtracted_exact.extend(exact_test_names(filter, true));
    }
    let roster: BTreeSet<String> = IGNORED_TESTS_OUTSIDE_THE_LANE
        .iter()
        .map(|(name, _)| (*name).to_owned())
        .collect();
    let unclaimed: Vec<&String> = subtracted.difference(&roster).collect();
    assert!(
        unclaimed.is_empty(),
        "a gate subtracts {unclaimed:?} by `not test(NAME)` / `!test(NAME)`, and \
         IGNORED_TESTS_OUTSIDE_THE_LANE does not say whose budget it spends"
    );
    let nightly: BTreeSet<String> = NIGHTLY_CELLS
        .iter()
        .map(|cell| cell.test.to_owned())
        .collect();
    let unhanded: Vec<&String> = subtracted_exact
        .iter()
        .filter(|name| !nightly.iter().any(|cell| names_test(name, cell)))
        .collect();
    assert!(
        unhanded.is_empty(),
        "a gate subtracts {unhanded:?} by `not test(=NAME)`, and no NIGHTLY_CELLS row \
         hands it to L2"
    );
}

/// COUNTERFACTUALS for [`read_gate_nextest`]'s first rule: each canonical shape is read
/// as the run it spells, and a line naming nextest in any other form is refused — with
/// a clean filter as with a libtest `--skip` or a negated group.
#[test]
fn a_line_naming_nextest_is_one_canonical_run_or_it_is_refused() {
    const SKIP: &str = "-E 'binary(a)' -- --skip n";
    const NEGATION: &str = "-E 'binary(a) & not (test(n))'";
    const CLEAN: &str = "-E 'binary(a)'";
    let mut failures = Vec::new();

    // The canonical shapes, each as the justfile writes it.
    for (body, text, filter) in [
        (
            "cargo nextest run --workspace",
            "cargo nextest run --workspace",
            None,
        ),
        (
            "cargo nextest run --workspace --no-run",
            "cargo nextest run --workspace --no-run",
            None,
        ),
        (
            "cargo nextest run --workspace -P measurement --test-threads 1",
            "cargo nextest run --workspace -P measurement --test-threads 1",
            None,
        ),
        (
            "KATA_SANDBOX_REQUIRE_LIVE=1 \\\n    cargo nextest run --workspace -P live-smoke --test-threads=1 \\\n    --run-ignored only --success-output final -E 'binary(a) & not test(=n)'",
            "cargo nextest run --workspace -P live-smoke --test-threads=1 --run-ignored only \
             --success-output final -E binary(a) & not test(=n)",
            Some("binary(a) & not test(=n)"),
        ),
        (
            "KATA_LIVE_SMOKE=1 KATA_SANDBOX_REQUIRE_LIVE=1 cargo nextest run --run-ignored all -E 'binary(a)'",
            "cargo nextest run --run-ignored all -E binary(a)",
            Some("binary(a)"),
        ),
        (
            "env -u KATA_E3_AGENT -u KATA_E3_FUNDED \\\n\tcargo nextest run -P soak -E 'binary(a)' --success-output immediate",
            "cargo nextest run -P soak -E binary(a) --success-output immediate",
            Some("binary(a)"),
        ),
        (
            "\t  cargo nextest run  --run-ignored\tignored-only  -E 'test(=m::c) | test($x \"y\")'  ",
            "cargo nextest run --run-ignored ignored-only -E test(=m::c) | test($x \"y\")",
            Some("test(=m::c) | test($x \"y\")"),
        ),
    ] {
        let runs = read_gate_nextest(body).runs;
        let expected = vec![NextestRun {
            text: text.to_owned(),
            filter: filter.map(str::to_owned),
        }];
        if runs != expected {
            failures.push(format!("{body:?} read as {runs:?}"));
        }
    }

    // (template, canonical). A canonical template is refused only for its tail; any
    // other is refused whatever its tail, and no run is read from it.
    let templates: &[(&str, bool)] = &[
        ("cargo nextest run {}", true),
        ("    cargo nextest run --workspace \\\n        {}", true),
        ("KATA_LIVE_SMOKE=1 cargo nextest run {}", true),
        ("env -u KATA_E3_AGENT cargo nextest run {}", true),
        // Just joins a continuation with its leading blanks removed.
        ("cargo nex\\\n    test run {}", true),
        ("cargo nextest run --work\\\nspace {}", true),
        ("cargo nextest run {} \\", true),
        // A second command, a group, a keyword or a redirection on the line.
        (
            "cargo nextest run --workspace --no-run && cargo nextest run {}",
            false,
        ),
        ("true; cargo nextest run {}", false),
        ("false || cargo nextest run {}", false),
        ("echo x | cargo nextest run {}", false),
        ("cargo nextest run {} | tee log", false),
        ("cargo nextest run {} &", false),
        ("sleep 1 & cargo nextest run {}", false),
        ("(cargo nextest run {})", false),
        ("( cargo nextest run {} )", false),
        ("{ cargo nextest run {}; }", false),
        ("if cargo nextest run {}; then :; fi", false),
        ("while ! cargo nextest run {}; do :; done", false),
        ("f() { cargo nextest run {}; }; f", false),
        ("cargo nextest run > log {}", false),
        ("cargo nextest run {} 2>&1", false),
        ("cargo nextest run {} &>log", false),
        ("2>/dev/null cargo nextest run {}", false),
        ("cargo nextest run {} || exit $?", false),
        ("cargo nextest run {} # the suite", false),
        ("# cargo nextest run {}", false),
        // Another spelling of the command, or a word before it.
        ("cargo-nextest nextest run {}", false),
        ("~/.cargo/bin/cargo-nextest nextest run {}", false),
        ("/usr/bin/cargo nextest run {}", false),
        ("cargo nextest r {}", false),
        ("cargo nextest list {}", false),
        ("cargo nextest bench {}", false),
        ("cargo nextest --no-pager run {}", false),
        ("cargo +stable nextest run {}", false),
        ("cargo --locked nextest run {}", false),
        ("cargo llvm-cov nextest {}", false),
        ("\\cargo \"nextest\" r'un' {}", false),
        ("'cargo' nextest run {}", false),
        ("cargo NEXTEST run {}", false),
        ("@cargo nextest run {}", false),
        ("-cargo nextest run {}", false),
        ("@-cargo nextest run {}", false),
        ("KATA=1 cargo nextest run {}", false),
        ("NEXTEST_PROFILE=ci cargo run {}", false),
        ("KATA_LIVE_SMOKE=2 cargo nextest run {}", false),
        (
            "KATA_LIVE_SMOKE=1 env -u KATA_X cargo nextest run {}",
            false,
        ),
        (
            "env -u KATA_X KATA_LIVE_SMOKE=1 cargo nextest run {}",
            false,
        ),
        ("env -u HOME cargo nextest run {}", false),
        ("env cargo nextest run {}", false),
        ("env -C dir cargo nextest run {}", false),
        ("env -S 'cargo nextest run' {}", false),
        ("command cargo nextest run {}", false),
        ("command -p cargo nextest run {}", false),
        ("exec cargo nextest run {}", false),
        ("builtin command cargo nextest run {}", false),
        ("timeout 600 cargo nextest run {}", false),
        ("xargs cargo nextest run {}", false),
        ("nice -n 5 cargo nextest run {}", false),
        ("flock -o /tmp/l cargo nextest run {}", false),
        ("time cargo nextest run {}", false),
        // A string or a substitution the shell runs.
        ("x=$(cargo nextest run {})", false),
        ("echo \"$(cargo nextest run {})\"", false),
        ("echo `cargo nextest run {}`", false),
        ("diff <(cargo nextest run {}) /dev/null", false),
        ("bash -c \"cargo nextest run {}\"", false),
        ("bash -euc \"cargo nextest run {}\"", false),
        ("eval \"cargo nextest run {}\"", false),
        ("bash <<< \"cargo nextest run {}\"", false),
        ("source /dev/stdin <<< \"cargo nextest run {}\"", false),
        ("trap \"cargo nextest run {}\" EXIT", false),
        ("printf '%s\\n' \"cargo nextest run {}\" | sh", false),
        // A name the shell, or Just, holds the word under.
        ("$CARGO nextest run {}", false),
        ("cargo nextest $run {}", false),
        ("eval \"cargo nextest $r {}\"", false),
        ("CARGO_ALIAS_T='nextest run' cargo t {}", false),
        ("alias t='cargo nextest run'; t {}", false),
        ("x='cargo nextest run'; $x {}", false),
        ("c=cargo; s=nextest; $c $s run {}", false),
        ("arr=(cargo nextest run); \"${arr[@]}\" {}", false),
        ("export NEXTEST_RUN_IGNORED=all; cargo test {}", false),
        // A continuation that joins two words into one Just runs.
        ("cargo nextest run --workspace\\\n{}", false),
    ];
    for (template, canonical) in templates {
        for tail in [SKIP, NEGATION] {
            let body = template.replace("{}", tail);
            if read_gate_nextest(&body).refusals.is_empty() {
                failures.push(format!("not refused: {body:?}"));
            }
        }
        let body = template.replace("{}", CLEAN);
        let read = read_gate_nextest(&body);
        if *canonical {
            if !read.refusals.is_empty() {
                failures.push(format!("refused: {body:?}: {:?}", read.refusals));
            }
            if read.runs.len() != 1 || read.runs[0].filter.as_deref() != Some("binary(a)") {
                failures.push(format!("not read: {body:?}: {:?}", read.runs));
            }
        } else {
            if read.refusals.is_empty() {
                failures.push(format!("not refused: {body:?}"));
            }
            if !read.runs.is_empty() {
                failures.push(format!("read a run from: {body:?}"));
            }
        }
    }

    // Whole bodies: each must be refused. No shell variable is resolved, so a filter or
    // an argument held in one is refused where it is used.
    for body in [
        "expr='binary(a)'\ncargo nextest run -E \"$expr\"\n",
        "expr='binary(a)'\nprintf -vexpr '%s' \"$expr and not (test(n))\"\ncargo nextest run -E \"$expr\"\n",
        // Each way the shell can write a variable that an assignment-following reader
        // would have trusted.
        "x='binary(a)'\nprintf -vx '%s' 'binary(a) & not (test(n))'\ncargo nextest run -E \"$x\"\n",
        "x='binary(a)'\nn=x\nprintf -v \"$n\" '%s' 'binary(a) & not (test(n))'\ncargo nextest run -E \"$x\"\n",
        "x='binary(a)'\nread -r x <<< 'binary(a) & not (test(n))'\ncargo nextest run -E \"$x\"\n",
        "x='binary(a)'\ne=eval\n$e \": ; x='binary(a) & not (test(n))'\"\ncargo nextest run -E \"$x\"\n",
        "x='binary(a)'\nsource /dev/stdin <<'EOF'\nx='binary(a) & not (test(n))'\nEOF\ncargo nextest run -E \"$x\"\n",
        "cargo --config 'alias.t=\"nextest run\"' t -E 'binary(a)' -- --skip n\n",
        "arr=(cargo nextest run -E 'binary(a)' -- --skip n); timeout 9 \"${arr[@]}\"\n",
        "x=';'\ncargo nextest run $x -E 'binary(a)'\n",
        "x='--'\ncargo nextest run '$x' -E 'binary(a)'\n",
        "cargo nextest run -E 'binary(a)' \"$@\"\n",
        "bash <<'EOF'\ncargo nextest run -E 'binary(a)' -- --skip n\nEOF\n",
        "cat <<'EOF'\ndon't cargo nextest run\nEOF\n",
        "./target/nextest run\n",
        "ls target/nextest\n",
        "pgrep -x 'cargo-nextest' | xargs -I{} cargo-nextest nextest run\n",
        "pgrep -f 'cargo|rustc|nextest'\n",
        "pgrep -f 'cargo-nextest'\n",
        "pgrep -x \"cargo-nextest\"\n",
        "pgrep -x 'cargo-nextest nextest run'\n",
        "echo 'a\n'; cargo nextest run -E 'binary(a)'; echo '\nb'\n",
        // Every libtest skip spelling, and every other word after the options.
        "cargo nextest run -E 'binary(a)' -- --skip x",
        "cargo nextest run -E 'binary(a)' -- --exact --skip=x --skip y",
        "cargo nextest run -E 'binary(a)' -- '--skip' x",
        "cargo nextest run -E 'binary(a)' -- \"--skip=x\"",
        "cargo nextest run -E 'binary(a)' -- \\--skip x",
        "cargo nextest run -E 'binary(a)' -- --sk'ip' x",
        "cargo nextest run -E 'binary(a)' -- --sk{i,}p x",
        "cargo nextest run -E 'binary(a)' -- --sk?p x",
        "cargo nextest run -E 'binary(a)' -- $skip x",
        "cargo nextest run -E 'binary(a)' -- $'--skip' x",
        "cargo nextest run -E 'binary(a)' -- \"$(echo --skip)\" x",
        "cargo nextest run -E 'binary(a)' -- '--skip x'",
        "cargo nextest run -E 'binary(a)' --skip x",
        "cargo nextest run -E 'binary(a)' --",
        "cargo nextest run -E 'binary(a)' && echo --skip x",
        // Every other spelling of the filter flag, and every other narrowing.
        "cargo nextest run \"-E\" 'binary(a)'",
        "cargo nextest run -E'binary(a)'",
        "cargo nextest run -E x'binary(a)'",
        "cargo nextest run -E='binary(a)'",
        "cargo nextest run -E=binary",
        "cargo nextest run -vE 'binary(a)'",
        "cargo nextest run --filterset 'binary(a)'",
        "cargo nextest run --filterset='binary(a)'",
        "cargo nextest run --filter-expr 'binary(a)'",
        "cargo nextest run -E \"binary(a)\"",
        "cargo nextest run -E binary",
        "cargo nextest run -E binary(a)",
        "cargo nextest run -E binary(a)|binary(b)",
        "cargo nextest run -E \\'binary(a)\\'",
        "cargo nextest run -E",
        "cargo nextest run -E ''",
        "cargo nextest run -E ' '",
        "cargo nextest run -E 'binary(a)",
        "cargo nextest run -E 'binary(a)'x",
        "cargo nextest run -E 'binary(a)'--no-run",
        "cargo nextest run -E 'binary(a)' -E 'binary(b)'",
        "cargo nextest run -E 'binary(a)' 'binary(b)'",
        "cargo nextest run a_name_filter",
        "cargo nextest run -p kata",
        "cargo nextest run -j 1",
        "cargo nextest run --exact",
        "cargo nextest run --partition count:1/2",
        "cargo nextest run --ignore-default-filter",
        "cargo nextest run --test-threads=4",
        "cargo nextest run --test-threads 4",
        "cargo nextest run --test-threads=1 --test-threads 1",
        "cargo nextest run -P ci",
        "cargo nextest run -P",
        "cargo nextest run --run-ignored default",
        "cargo nextest run --success-output never",
        "cargo nextest run --workspace --workspace",
        // Each negation `unread_negations` names, in a canonical run's filter.
        "cargo nextest run -E 'binary(a) & not test(/kill/)'",
        "cargo nextest run -E 'binary(a) - test(x)'",
        "cargo nextest run -E 'binary(a) & test($x)'",
    ] {
        if read_gate_nextest(body).refusals.is_empty() {
            failures.push(format!("not refused: {body:?}"));
        }
    }
    let interpolated = format!("cargo nextest run -E 'binary(a) & test({DYNAMIC})'");
    let parameter = format!("cargo nextest run -E 'binary(a)' {DYNAMIC}");
    for body in [interpolated.as_str(), parameter.as_str()] {
        if read_gate_nextest(body).refusals.is_empty() {
            failures.push(format!("not refused: {body:?}"));
        }
    }

    // NOT refused, and no run read: the two texts `judged_text` drops, and, in a body
    // that never writes the word, the word produced at run time behind a command word
    // that is not a written `cargo` — out of scope (verification.md).
    for body in [
        "$c $s run -E 'binary(a)' -- --skip n\n",
        "root=\"$(pwd)\"\nbin=\"$root/target/debug/kata\"\n$bin run x\n",
        "rm -f target/nextest/default/junit.xml target/nextest/live-smoke/junit.xml\n",
        "mv target/nextest/measurement/junit.xml \"$junit/test-measurement.xml\"\n",
        "for pid in $(pgrep -x 'cargo' 2>/dev/null; pgrep -x 'cargo-nextest' 2>/dev/null; true); do :; done\n",
        "c\"\"argo nex\"\"test run -E 'binary(a)' -- --skip n\n",
        "n=nex; n+=test\n\"$c\" \"$n\" run -- --skip n\n",
        "eval \"$line\"\n",
        "bash <<< \"$line\"\n",
        "printf '%s' 'cargo nex' 'test run' | sh\n",
        "… | xargs cargo\n",
        "bash scripts/x.sh\n",
        "\"$kata_bin\" run x\n",
    ] {
        let read = read_gate_nextest(body);
        if !read.refusals.is_empty() || !read.runs.is_empty() {
            failures.push(format!("{body:?}: {:?} {:?}", read.runs, read.refusals));
        }
    }
    assert!(
        failures.is_empty(),
        "{} failure(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
    // A refusal names the body line the run starts on.
    let refusals = read_gate_nextest("\n\nFOO=1 \\\n  cargo nextest run\n").refusals;
    assert_eq!(refusals.len(), 1, "{refusals:?}");
    assert!(refusals[0].starts_with("body line 3: "), "{refusals:?}");
}

/// COUNTERFACTUALS for [`undecided_cargo_subcommands`]: a `cargo` whose next word the
/// shell or Just could decide is refused, a plain subcommand and a longer name are not.
#[test]
fn a_cargo_subcommand_the_shell_could_decide_is_refused() {
    let interpolated_subcommand = format!("cargo {DYNAMIC} --workspace");
    let interpolated_command = format!("cargo{DYNAMIC} build");
    let split_toolchain = format!("cargo +{DYNAMIC} nex\"\"test run");
    for body in [
        "cargo nex\"\"test run -E 'binary(a)' -- --skip n",
        "cargo nex''test run",
        "cargo \"nex\"test run",
        "cargo ne\\xtest run",
        "cargo nex${empty}test run",
        "cargo $sub run",
        "cargo \"$@\"",
        "cargo $(echo nex)test run",
        "cargo `echo nex`test run",
        "cargo nex{test,} run",
        "cargo nex* run",
        "cargo n?xtest run",
        "cargo [n]extest run",
        "cargo ne@(x)test run",
        "cargo $'nex\\x74est' run",
        "cargo --locked build",
        "cargo --config 'alias.t=\"x\"' t",
        "cargo -Zunstable-options build",
        "cargo 2>/dev/null nex''test run",
        "cargo >log nex''test run",
        "cargo <in nex''test run",
        "cargo>log nex''test run",
        "cargo&>log nex''test run",
        "cargo$empty nex''test run",
        "cargo\\ nex''test run",
        "cargo{,} nex''test run",
        "cargo* nex''test run",
        "\"cargo\" nex''test run",
        "'cargo' nex''test run",
        "\"${CARGO:-cargo}\" nex''test run",
        "$(command -v cargo) nex''test run",
        "`which cargo` nex''test run",
        "cargo nex` `test run",
        "cargo` ` nex` `test run",
        "cargo build`echo`",
        "cargo`echo -n` nex''test run",
        "cargo-nex\"\"test nex\"\"test run",
        "cargo-$tool nex''test run",
        "/usr/bin/cargo nex''test run",
        "env cargo nex''test run",
        "timeout 9 cargo nex''test run",
        "x=1 cargo\tnex''test run",
        "cargo \\\n    nex''test run",
        // A script recipe's shell keeps a continuation's blanks: `exec    cargo …`.
        "#!/usr/bin/env bash\nexec\\\n    cargo nex''test run",
        "cargo +stable nex''test run",
        "cargo +\"$toolchain\" build",
        "cargo +$toolchain build",
        "cargo \"build\"",
        interpolated_subcommand.as_str(),
        interpolated_command.as_str(),
        split_toolchain.as_str(),
    ] {
        assert!(
            !read_gate_nextest(body).refusals.is_empty(),
            "not refused: {body:?}"
        );
    }
    let dated_toolchain = format!("cargo +{DYNAMIC} fmt -- --check");
    for body in [
        "cargo build --workspace --bins --examples",
        "CARGO_TARGET_DIR=\"$dir\" cargo build --workspace --release --locked --offline",
        "if ! cargo check -p kata-types --all-targets >\"$log\" 2>&1; then",
        "cargo build -p kata-toolhost --target x86_64-unknown-linux-musl || exit $?",
        "cargo clippy --workspace --all-targets --all-features -- -D warnings",
        "cargo test --doc --workspace",
        "cargo deny check --hide-inclusion-graph >\"$log\" 2>&1",
        "cargo +nightly-2026-01-01 fmt",
        dated_toolchain.as_str(),
        "x=$(cargo metadata)",
        "cargo",
        "cargo; cargo | cat",
        "echo \"deny: cargo-deny FAILED (exit $rc).\" >&2",
        "echo \"  dependency. Compare 'cargo bloat\" >&2",
        "echo \"deny-fresh: 'cargo deny fetch db' updated no advisory database\" >&2",
        "for head in \"${CARGO_HOME:-$HOME/.cargo}\"/advisory-dbs/*/.git/FETCH_HEAD; do",
        "# hold cargo's build lock; the PATH contains \"cargo\" — so a cargo at PPID 1",
        "for pid in $(pgrep -x 'cargo' 2>/dev/null; pgrep -x 'cargo-clippy' 2>/dev/null; true); do",
        "xcargo \"$x\"; my_cargo $y; target/.cargo \"$z\"",
        // Just joins a linewise recipe's continuation without its blanks, so this runs
        // `execcargo`, not cargo.
        "exec\\\n    cargo nex''test run",
    ] {
        let refusals = read_gate_nextest(body).refusals;
        assert!(refusals.is_empty(), "refused: {body:?}: {refusals:?}");
    }
    // `pgrep -x 'NAME'` is dropped only as that exact text.
    for body in [
        "pgrep -x \"cargo\" 2>/dev/null",
        "pgrep -f 'cargo' 2>/dev/null",
        "pgrep -x 'cargo $x'",
    ] {
        assert!(
            !read_gate_nextest(body).refusals.is_empty(),
            "not refused: {body:?}"
        );
    }
}

/// COUNTERFACTUALS for [`nextest_outside_body_text`] and for [`read_gates`] end to
/// end, on synthetic justfiles: the word written into a variable, a setting, a
/// parameter's name or default, a dependency argument, an attribute or a body
/// interpolation is refused; a string Just only builds, a recipe no root reaches, the
/// comment above a recipe and what Just's JSON leaves out are not.
#[test]
fn nextest_written_outside_the_text_of_a_body_is_refused() {
    let refusals = |source: &str| {
        read_gates(&parse_justfile_source(source), &["gate"])
            .refusals
            .into_iter()
            .collect::<Vec<_>>()
    };
    let mut failures = Vec::new();
    for (source, refused) in [
        (
            "runner := \"cargo nextest run\"\ngate:\n    {{ runner }} -- --skip n\n",
            "the variable `runner` names nextest",
        ),
        (
            "export NEXTEST_PROFILE := \"ci\"\ngate:\n    true\n",
            "the variable `NEXTEST_PROFILE` names nextest",
        ),
        (
            "sub := \"nextest\"\nunused:\n    true\ngate:\n    true\n",
            "the variable `sub` names nextest",
        ),
        (
            "set shell := [\"bash\", \"-c\", \"cargo nextest run; $0\"]\ngate:\n    true\n",
            "a `set` setting names nextest",
        ),
        (
            "gate runner=\"cargo nextest run\":\n    {{ runner }} -- --skip n\n",
            "`gate`: the parameter `runner` names nextest",
        ),
        (
            "gate: (sub \"nextest\")\nsub word:\n    true {{ word }}\n",
            "`gate`: a dependency argument names nextest",
        ),
        (
            "gate:\n    just sub\nsub: (leaf \"cargo-nextest\")\nleaf word:\n    true\n",
            "`sub`: a dependency argument names nextest",
        ),
        (
            "gate $NEXTEST_RUN_IGNORED=\"all\":\n    cargo nextest run --workspace\n",
            "`gate`: the parameter `NEXTEST_RUN_IGNORED` names nextest",
        ),
        (
            "[env(\"NEXTEST_RUN_IGNORED\", \"all\")]\ngate:\n    cargo nextest run --workspace\n",
            "`gate`: an attribute names nextest",
        ),
        (
            "gate:\n    true\n    {{ \"cargo nextest run -- --skip n\" }}\n",
            "`gate`, body line 2: an interpolation names nextest",
        ),
        (
            "gate:\n    #!/usr/bin/env bash\n    c\"\"argo {{ `echo NexTest` }} run -- --skip n\n",
            "`gate`, body line 2: an interpolation names nextest",
        ),
    ] {
        let refusals = refusals(source);
        if !refusals.iter().any(|refusal| refusal.trim() == refused) {
            failures.push(format!("{source:?}: {refusals:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} failure(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
    for source in [
        // A recipe no gate root reaches.
        "gate:\n    true\nother runner=\"cargo nextest run\":\n    {{ runner }}\n",
        "gate:\n    true\n[env(\"NEXTEST_PROFILE\", \"ci\")]\nother $NEXTEST_RETRIES=\"1\":\n    {{ \"nextest\" }}\n",
        // The comment above a recipe: Just keeps it as the recipe's doc, and runs none
        // of it.
        "# Runs `cargo nextest run`.\ngate:\n    true\n",
        // What `just --dump` leaves out of its JSON.
        "set script-interpreter := [\"cargo\", \"nextest\"]\nunexport NEXTEST_PROFILE\ngate:\n    true\n",
        // A string Just builds: not seen.
        "word := \"nex\" + \"test\"\ngate:\n    c\"\"argo {{ word }} run -- --skip n\n",
    ] {
        assert_eq!(refusals(source), Vec::<String>::new(), "{source}");
    }
    // End to end: a reachable recipe's line and its run, each under the recipe's name.
    let justfile = parse_justfile_source(
        "gate: unit\n    just live\nunit:\n    cargo nextest run --workspace\n\
         live:\n    #!/usr/bin/env bash\n    cargo nextest run -E 'binary(a)' -- --skip n\n\
         unreached:\n    cargo nextest run -- --skip n\n",
    );
    let gates = read_gates(&justfile, &["gate"]);
    assert_eq!(
        gates.runs,
        vec![(
            "unit".to_owned(),
            NextestRun {
                text: "cargo nextest run --workspace".to_owned(),
                filter: None,
            }
        )]
    );
    // A recipe two roots reach is read once.
    assert_eq!(read_gates(&justfile, &["gate", "unit"]).runs, gates.runs);
    // The script recipe's `#!` line and its run, each refused.
    let refusals: Vec<&String> = gates.refusals.iter().collect();
    assert_eq!(refusals.len(), 2, "{refusals:?}");
    for (refusal, line) in refusals.iter().zip(1..) {
        assert!(
            refusal.starts_with(&format!(
                "  `live`, body line {line}: the body names nextest, and this line is not a \
                 canonical run: "
            )),
            "{refusals:?}"
        );
    }
}

/// Each way this repository's own text could alias a cargo subcommand to `nextest`,
/// which [`undecided_cargo_subcommands`] — taking a plain subcommand at its word — would
/// not see: the string `alias` anywhere in the root `.cargo/config.toml` (a table, a
/// dotted or quoted key, a comment); a `.cargo/config` beside it, which cargo also
/// reads; `CARGO_ALIAS_` anywhere in the justfile.
fn cargo_alias_definitions(config: &str, second_config: bool, justfile: &str) -> Vec<&'static str> {
    let mut out = Vec::new();
    if config.contains("alias") {
        out.push("`.cargo/config.toml` names `alias`");
    }
    if second_config {
        out.push("a `.cargo/config` stands beside `.cargo/config.toml`");
    }
    if justfile.contains("CARGO_ALIAS_") {
        out.push("the justfile names `CARGO_ALIAS_`");
    }
    out
}

/// No cargo alias this repository's own text defines can rename a subcommand to
/// `nextest` ([`cargo_alias_definitions`]). An alias on the command line (`cargo
/// --config …`) is [`undecided_cargo_subcommands`]'s. NOT checked: a cargo
/// configuration in a directory a recipe changes into, the host's own, and the
/// environment's `CARGO_ALIAS_*`.
///
/// COUNTERFACTUAL: on synthetic text, each spelling of an alias in the configuration,
/// the second configuration file and the environment name in the justfile are each
/// named, and a configuration without one is not.
#[test]
fn the_repository_defines_no_cargo_alias() {
    let config = std::fs::read_to_string(repo_root().join(".cargo/config.toml"))
        .expect("the repository's cargo configuration");
    assert_eq!(
        cargo_alias_definitions(
            &config,
            repo_root().join(".cargo/config").exists(),
            &justfile_text().source
        ),
        Vec::<&str>::new()
    );

    const CLEAN: &str = "[build]\njobs = 4\n";
    for config in [
        "[alias]\nt = \"nextest run\"\n",
        "alias.t = \"nextest run\"\n",
        "\"alias\".t = [\"nextest\", \"run\"]\n",
        "[build]\nalias = { t = \"nextest run\" }\n",
    ] {
        assert_eq!(
            cargo_alias_definitions(config, false, "gate:\n    true\n"),
            ["`.cargo/config.toml` names `alias`"],
            "{config}"
        );
    }
    assert_eq!(
        cargo_alias_definitions(CLEAN, true, "gate:\n    true\n"),
        ["a `.cargo/config` stands beside `.cargo/config.toml`"]
    );
    assert_eq!(
        cargo_alias_definitions(CLEAN, false, "gate:\n    export CARGO_ALIAS_T=\"$x\"\n"),
        ["the justfile names `CARGO_ALIAS_`"]
    );
    assert_eq!(
        cargo_alias_definitions(CLEAN, false, "gate:\n    true\n"),
        Vec::<&str>::new()
    );
}

/// COUNTERFACTUALS for [`unread_negations`] and the `!` arm of [`excluded_test_names`]:
/// each form read, each form refused, on synthetic input.
#[test]
fn the_negation_reader_reads_both_spellings_and_refuses_every_other_negation() {
    for read in [
        "(binary(smokes) or binary(live_smoke)) and not test(smoke_ro)",
        "binary(a) & !test(x) & !test(=y)",
        "package(kata) & binary(oci_main_live) & not test(=a_b) & test(=m::c)",
        "test(a) + test(b)",
    ] {
        assert_eq!(unread_negations(read), Vec::<String>::new(), "{read}");
    }
    for refused in [
        "binary(a) & not test(/kill_mid/)",
        "binary(a) & not test(#kill*)",
        "binary(a) & not test(~kill)",
        "binary(a) & not (test(x) | test(y))",
        "(binary(a) | binary(b)) & not binary(b)",
        "binary(a) & !package(p)",
        "binary(a) - test(x)",
        "binary(a) & not not test(x)",
        "binary(a) | none()",
        "binary(a) & test(x y)",
        // A negated GROUP around one test: nextest subtracts it exactly as it does
        // `not test(x)`, but the text before `test(` ends in `(`, not in a negation.
        "binary(a) & not (test(x))",
        "binary(a) & !(test(=x))",
        "binary(a) & not(test(x))",
        "binary(a) & ! ( (test(x)) )",
    ] {
        assert!(
            !unread_negations(refused).is_empty(),
            "{refused} must be refused"
        );
    }
    assert!(!unread_negations(&format!("test({DYNAMIC})")).is_empty());
    assert_eq!(
        excluded_test_names("binary(a) & !test(x) and not test(y) & !test(=z) & test(w)"),
        ["x", "y"]
            .into_iter()
            .map(String::from)
            .collect::<BTreeSet<_>>()
    );
}

/// Every test function in one test-binary source file, with whether it is `#[ignore]`d.
///
/// A function counts when the attribute block right above it carries a test attribute
/// (`#[test`, `#[tokio::test`, `#[rstest`); `#[ignore` anywhere in that block marks it
/// ignored. An attribute may span lines (a long `#[ignore = "…"]` reason) up to the line
/// that ends in `]`. Doc comments may sit between the attributes; any other line ends
/// the block.
fn test_functions(source: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    let (mut test, mut ignored, mut in_attribute) = (false, false, false);
    for line in source.lines() {
        let trimmed = line.trim();
        if in_attribute {
            in_attribute = !trimmed.ends_with(']');
            continue;
        }
        if trimmed.starts_with("#[") {
            test |= ["#[test", "#[tokio::test", "#[rstest"]
                .iter()
                .any(|attribute| trimmed.starts_with(attribute));
            ignored |= trimmed.starts_with("#[ignore");
            in_attribute = !trimmed.ends_with(']');
            continue;
        }
        if trimmed.starts_with("//") || trimmed.is_empty() {
            continue;
        }
        if test {
            let signature = trimmed.strip_prefix("pub ").unwrap_or(trimmed);
            let signature = signature.strip_prefix("async ").unwrap_or(signature);
            if let Some(rest) = signature.strip_prefix("fn ") {
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if !name.is_empty() {
                    out.push((name, ignored));
                }
            }
        }
        test = false;
        ignored = false;
    }
    out
}

/// binary name -> (its test functions with whether each is `#[ignore]`d, whether the
/// binary is capability-conditional).
type BinaryCells = BTreeMap<String, (Vec<(String, bool)>, bool)>;

/// The pure core of the run-mode rule: one line per live-layer nextest command that
/// re-runs host-free cells or selects nothing.
///
/// For each binary a line names, an offender is:
///   * `--run-ignored all` on a binary that is NOT capability-conditional, selecting
///     any non-ignored cell — that cell is host-free, `just test` already ran it in
///     parallel, and here it runs again, serially;
///   * `--run-ignored only` selecting no ignored cell of the binary — a filter clause
///     that runs nothing;
///   * `--run-ignored only` on a capability-conditional binary, selecting any
///     non-ignored cell — that cell asserts only under `KATA_SANDBOX_REQUIRE_LIVE` (and
///     its siblings), which `just test` does not set, so `only` drops the one run that
///     makes it a proof.
fn run_mode_offenders(lines: &[(String, String)], binaries: &BinaryCells) -> Vec<String> {
    let mut out = Vec::new();
    for (recipe, line) in lines {
        let mode = run_ignored_mode(line);
        let selection = line_selection(line);
        let mut named = BTreeSet::new();
        let mut rest = line.as_str();
        while let Some(at) = rest.find("binary(") {
            rest = &rest[at + "binary(".len()..];
            if let Some(close) = rest.find(')') {
                named.insert(rest[..close].trim_start_matches('=').to_owned());
            }
        }
        for binary in named {
            let Some((tests, capability)) = binaries.get(&binary) else {
                continue;
            };
            let selected: Vec<&(String, bool)> = tests
                .iter()
                .filter(|(name, _)| selection.selects(name))
                .collect();
            match mode {
                "all" if !capability => {
                    let host_free: Vec<&str> = selected
                        .iter()
                        .filter(|(_, ignored)| !ignored)
                        .map(|(name, _)| name.as_str())
                        .collect();
                    if !host_free.is_empty() {
                        out.push(format!(
                            "  {recipe}: `--run-ignored all` re-runs {} host-free cell(s) of \
                             `{binary}` (e.g. {}) that `just test` already ran",
                            host_free.len(),
                            host_free[0]
                        ));
                    }
                }
                "only" => {
                    if !selected.iter().any(|(_, ignored)| *ignored) {
                        out.push(format!(
                            "  {recipe}: `--run-ignored only` selects no ignored cell of `{binary}`"
                        ));
                    }
                    let knob_asserted = selected.iter().filter(|(_, ignored)| !ignored).count();
                    if *capability && knob_asserted > 0 {
                        out.push(format!(
                            "  {recipe}: `--run-ignored only` drops {knob_asserted} \
                             knob-asserted cell(s) of capability-conditional `{binary}`"
                        ));
                    }
                }
                _ => {}
            }
        }
    }
    out
}

/// The live layers run each binary in the mode its cells need: no host-free cell twice.
///
/// REFUSED, per nextest command line reachable from `gate-containment` or `gate-nightly`
/// and per `binary(X)` it names: `--run-ignored all` selecting a NON-ignored cell of a
/// binary that is not capability-conditional (no `LIVE_CAPABILITY_MARKERS` in its
/// source) — a host-free cell `just test` already ran, re-run serially on the
/// containment lane; `--run-ignored only` selecting no ignored cell of a binary — a
/// clause that runs nothing; `--run-ignored only` on a capability-conditional binary
/// whose selection holds a non-ignored cell — a knob-asserted cell that then asserts
/// nowhere, since `just test` runs it without the knob, where it skips. At ba3b5c727 `oci-live-smoke`'s first step re-ran 74
/// `agent_turn_capsule` cells (92.6 s of 225.6 s) while its comment claimed one ignored
/// git-view cell that 6864208e6 had deleted. NOT refused: `--run-ignored all` on a
/// capability-conditional binary (`sandbox_seccomp_tests` asserts under the knob).
///
/// COUNTERFACTUAL: on synthetic input, `all` over a mixed host-free binary is named,
/// `only` over a binary with no ignored cell is named, `only` over a mixed capability
/// binary is named, `all` over a capability binary and `only` over a host-free binary's
/// ignored cell are not, and an exact `test(=…)` narrowing to the ignored cell clears
/// the `all` line.
#[test]
fn every_live_step_runs_each_binary_in_the_mode_its_cells_need() {
    let justfile = justfile_text();
    // A line naming nextest that is not a canonical run is refused by
    // `every_gate_filter_negates_only_in_a_form_this_file_reads`; each canonical run is
    // judged here as its text.
    let lines: Vec<(String, String)> = read_gates(&justfile, LIVE_LAYER_ROOTS)
        .runs
        .into_iter()
        .map(|(recipe, run)| (recipe, run.text))
        .collect();
    assert!(
        lines.iter().any(
            |(recipe, line)| recipe.starts_with("_oci-live-smoke-") && line.contains("binary(")
        ),
        "no `oci-live-smoke` nextest run names a binary; the scan is blind"
    );
    let binaries: BinaryCells = workspace_test_binaries()
        .into_iter()
        .filter(|(_, path)| *path != this_guard_file())
        .map(|(name, path)| {
            let source =
                binary_source(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
            let capability = LIVE_CAPABILITY_MARKERS
                .iter()
                .any(|(marker, _)| source.contains(marker));
            (name, (test_functions(&source), capability))
        })
        .collect();
    let offenders = run_mode_offenders(&lines, &binaries);
    assert!(
        offenders.is_empty(),
        "a live-layer step runs a binary in the wrong `--run-ignored` mode:\n{}\n\n\
         Use `--run-ignored only` for a binary whose live cells are `#[ignore]`d (its \
         host-free cells ride `just test`), and drop a binary with no ignored cell from \
         the filter unless it is capability-conditional.",
        offenders.join("\n")
    );

    let fixture = |capability| {
        BTreeMap::from([(
            "x".to_owned(),
            (
                vec![
                    ("live_cell".to_owned(), true),
                    ("host_free".to_owned(), false),
                ],
                capability,
            ),
        )])
    };
    let none_ignored = BTreeMap::from([(
        "y".to_owned(),
        (vec![("host_free".to_owned(), false)], false),
    )]);
    let line = |text: &str| vec![("r".to_owned(), text.to_owned())];
    let all = "cargo nextest run --workspace --run-ignored all -E 'binary(x)'";
    assert_eq!(run_mode_offenders(&line(all), &fixture(false)).len(), 1);
    assert!(run_mode_offenders(&line(all), &fixture(true)).is_empty());
    assert!(
        run_mode_offenders(
            &line(
                "cargo nextest run --workspace --run-ignored all -E 'binary(x) & test(=live_cell)'"
            ),
            &fixture(false)
        )
        .is_empty()
    );
    let only = "cargo nextest run --workspace --run-ignored only -E 'binary(x)'";
    assert!(run_mode_offenders(&line(only), &fixture(false)).is_empty());
    let dropped = run_mode_offenders(&line(only), &fixture(true));
    assert_eq!(dropped.len(), 1, "{dropped:?}");
    assert!(
        dropped[0].contains("drops 1 knob-asserted cell(s)"),
        "{dropped:?}"
    );
    assert_eq!(
        run_mode_offenders(
            &line("cargo nextest run --workspace --run-ignored only -E 'binary(y)'"),
            &none_ignored
        )
        .len(),
        1
    );
    assert_eq!(
        test_functions(
            "#[test]\n#[ignore = \"a reason \\\n    that wraps\"]\nfn live() {}\n\n/// doc\n#[tokio::test]\nasync fn host_free() {}\n"
        ),
        vec![("live".to_owned(), true), ("host_free".to_owned(), false)]
    );
}

/// The lane narrows by test NAME, so lane coverage must be judged by test name.
///
/// THE DEFECT THIS PINS. `every_capability_conditional_test_binary_rides_the_containment_lane`
/// certifies a binary as covered when the lane names it in a `binary(...)` filter.
/// A step that narrows by name — `just smoke shell_` → `(binary(smokes) or
/// binary(live_smoke)) and test(shell_)` — leaves both binaries reading as covered
/// while most of their `#[ignore]`d tests never run.
///
/// The step is `just smoke-no-budget`, whose include is unnarrowed, so the roster is
/// the two smokes it subtracts by name. This check is what proves the subtraction is
/// the ONLY reason anything is unrun, and it is what would name every receipt that
/// stopped running if the filter were narrowed.
///
/// COUNTERFACTUAL: make `just smoke shell_` the lane's step and this REDs with every
/// test that stopped running, headed by all four `smoke_main_local_socket_*` — the
/// receipts this file cites as the reason the lane exists.
#[test]
fn every_ignored_test_in_a_lane_selected_binary_is_run_or_declared() {
    let justfile = justfile_text();
    let binaries = workspace_test_binaries();
    let filters = live_layer_filters(&justfile);
    assert!(
        !filters.is_empty(),
        "parsed ZERO binary filters out of the containment lane graph"
    );

    let ignored: BTreeMap<String, Vec<String>> = binaries
        .iter()
        .filter(|(name, _)| filters.contains_key(*name))
        .filter_map(|(name, path)| {
            let source = binary_source(path).ok()?;
            let tests = ignored_test_names(&source);
            (!tests.is_empty()).then(|| (name.clone(), tests))
        })
        .collect();
    // NON-VACUITY: the lane's own product-path binaries carry `#[ignore]`d tests,
    // and a scan that found none would make this check green by seeing nothing.
    let found = ignored.values().map(Vec::len).sum::<usize>();
    assert!(
        found >= 10,
        "found only {found} `#[ignore]`d tests across the lane-selected binaries {:?} — \
         the attribute scan is not reading the tree",
        ignored.keys().collect::<Vec<_>>(),
    );

    // `IGNORED_TESTS_OUTSIDE_THE_LANE` declares the model-spend pair: a row
    // answers "who runs it".
    let declared: BTreeSet<String> = IGNORED_TESTS_OUTSIDE_THE_LANE
        .iter()
        .map(|(name, _)| (*name).to_string())
        .collect();
    let unrun = unrun_ignored_tests(&ignored, &filters, &declared);

    eprintln!(
        "LANE-TEST-COVERAGE ignored-tests={found} declared-unrun={} filters={filters:?}",
        declared.len(),
    );

    assert!(
        unrun.is_empty(),
        "{} `#[ignore]`d test(s) live in a binary the containment lane SELECTS but which \
         its test-name filter does not REACH, and no row claims them:\n{}\n\n\
         `just gate` cannot run them (`#[ignore]`), and the lane's filter does not select \
         them, so they are run by neither required lane while \
         `every_capability_conditional_test_binary_rides_the_containment_lane` reports \
         their binary as covered. The lane's product-path step \
         (`just smoke-no-budget`) runs every live smoke it is not explicitly told to \
         skip, so the usual cause is a narrowing that should not be there. Either widen \
         the lane's filter back, or add a row to IGNORED_TESTS_OUTSIDE_THE_LANE stating \
         who runs it — and note that a row has to name a model/API budget \
         reason (`the_lane_excludes_exactly_the_model_budget_smokes`).",
        unrun.len(),
        unrun.join("\n"),
    );
}

/// Every declared-unrun row must still name a real `#[ignore]`d test in a
/// lane-selected binary.
///
/// The same rule as `the_containment_allowlist_carries_no_stale_rows`, one
/// granularity down: a row for a test that was renamed, deleted, or that the lane
/// now RUNS is an exemption for a name that no longer means anything.
#[test]
fn the_unrun_ignored_test_roster_carries_no_stale_rows() {
    let justfile = justfile_text();
    let binaries = workspace_test_binaries();
    let filters = live_layer_filters(&justfile);

    let mut known: BTreeMap<String, String> = BTreeMap::new();
    for (name, path) in &binaries {
        if !filters.contains_key(name) {
            continue;
        }
        let Ok(source) = binary_source(path) else {
            continue;
        };
        for test in ignored_test_names(&source) {
            known.insert(test, name.clone());
        }
    }

    for (test, reason) in IGNORED_TESTS_OUTSIDE_THE_LANE {
        let binary = known.get(*test).unwrap_or_else(|| {
            panic!(
                "the unrun-ignored roster names `{test}`, which is not an `#[ignore]`d test \
                 in any lane-selected binary any more. A stale row reads as a decision \
                 somebody made about a test that exists.\nIts stated reason was: {reason}"
            )
        });
        let selected = filters
            .get(binary)
            .is_some_and(|selections| selections.iter().any(|selection| selection.selects(test)));
        assert!(
            !selected,
            "the roster says `{test}` is NOT run by the containment lane, and the lane's \
             filter for `{binary}` now selects it. Drop the row.\nIts stated reason was: \
             {reason}"
        );
    }
}

/// The lane subtracts EXACTLY the model-budget smokes, and says so in words.
///
/// THE DEFECT THIS PINS comes with the wide filter: the lane runs everything it is not
/// told to skip, and the `not test(...)` clauses are the only
/// thing standing between a required pre-push gate and two smokes that spend real
/// money. Three things can go wrong there and none is visible in a green run:
/// a THIRD clause quietly appears and a receipt stops running; a clause is
/// MISSPELLED, so it subtracts nothing and the lane starts spending; or a clause
/// stays but its stated reason drifts from "costs money" to "is flaky", which is
/// how an exclusion becomes permanent.
///
/// COUNTERFACTUAL: a narrowed step (`just smoke shell_`) reds this by name — the lane
/// runs 5 of the `#[ignore]`d live smokes instead of all the no-budget ones — alongside
/// `every_ignored_test_in_a_lane_selected_binary_is_run_or_declared`, which lists the
/// tests that stopped running.
#[test]
fn the_lane_excludes_exactly_the_model_budget_smokes() {
    let justfile = justfile_text();
    let binaries = workspace_test_binaries();
    let filters = lane_test_filters(&justfile, "gate-containment");

    // The binaries the lane subtracts FROM, and every `not test(...)` name it uses.
    let mut subtracted_from: BTreeSet<&String> = BTreeSet::new();
    let mut excluded: BTreeSet<String> = BTreeSet::new();
    for (binary, selections) in &filters {
        for selection in selections {
            if selection.exclude.is_empty() {
                continue;
            }
            subtracted_from.insert(binary);
            excluded.extend(selection.exclude.iter().cloned());
            // A subtraction under a NARROWED include is two filters doing the same
            // job, and the narrowing is the one that silently drops receipts.
            assert!(
                selection.include.iter().any(String::is_empty),
                "`{binary}` is narrowed by {:?} AND subtracted by {:?}. The lane's \
                 product-path step is supposed to run everything it is not explicitly \
                 told to skip; a positive narrowing on top of that hides whatever it \
                 fails to match.",
                selection.include,
                selection.exclude,
            );
        }
    }

    // NON-VACUITY: a lane that subtracts nothing makes every assertion below true by
    // having no subject — and would also mean the paid smoke is RUNNING.
    assert!(
        !excluded.is_empty(),
        "the containment lane subtracts NO test by name. Either `just smoke-no-budget` \
         lost its `not test(...)` clauses — in which case the required lane now drives \
         a real model turn and spends model budget on every push — or this parse \
         stopped reading them. Lane filters: {filters:?}"
    );

    // Every ignored test in the subtracted-from binaries, so "how much does the lane
    // run" is derived rather than asserted against a number somebody typed.
    let mut ignored_here: BTreeSet<String> = BTreeSet::new();
    for binary in &subtracted_from {
        let path = binaries
            .get(*binary)
            .unwrap_or_else(|| panic!("lane-selected binary `{binary}` exists in the tree"));
        let source =
            binary_source(path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        ignored_here.extend(ignored_test_names(&source));
    }
    let run_by_lane = ignored_here.len() - excluded.len();
    eprintln!(
        "LANE-SUBTRACTION binaries={subtracted_from:?} ignored={} excluded={} run={run_by_lane}",
        ignored_here.len(),
        excluded.len(),
    );
    // The wide filter as a LOWER BOUND, so a new smoke raises it and a re-narrowing
    // breaks it. Chosen above the narrow filters: `test(shell_)` runs 5 and
    // `test(smoke_main_local_socket_)` runs 4, so either would fail here.
    assert!(
        run_by_lane >= 15,
        "the containment lane runs only {run_by_lane} of the {} `#[ignore]`d live smokes. \
         It must run every one that spends no model budget; under a filter this narrow, \
         a smoke can stay red for a feature's whole lifetime because nothing runs it.",
        ignored_here.len(),
    );

    let declared: BTreeMap<&str, &str> = IGNORED_TESTS_OUTSIDE_THE_LANE.iter().copied().collect();
    for name in &excluded {
        // A MISSPELLED clause subtracts nothing, and nextest reports the same green for
        // a filter that matched no test as for one that matched. That failure spends
        // money rather than hiding a test, so it is checked against the tree.
        assert!(
            ignored_here.contains(name),
            "`just smoke-no-budget` subtracts `not test({name})`, which is not an \
             `#[ignore]`d test in any binary the lane selects: {ignored_here:?}. nextest \
             matches by substring and reports no error for a clause that matches nothing, \
             so a typo here does not fail the lane — it lets the excluded smoke RUN."
        );
        let reason = declared.get(name.as_str()).unwrap_or_else(|| {
            panic!(
                "`just smoke-no-budget` subtracts `not test({name})` and \
                 IGNORED_TESTS_OUTSIDE_THE_LANE does not say why. An exclusion with no \
                 stated runner is a receipt that stopped running and nobody noticed."
            )
        });
        let lowered = reason.to_lowercase();
        assert!(
            MODEL_BUDGET_WORDS
                .iter()
                .any(|word| lowered.contains(*word)),
            "`{name}` is subtracted from the required lane, and its stated reason names \
             none of {MODEL_BUDGET_WORDS:?}. The only sanctioned reason to skip a live \
             smoke here is that it spends real model/API budget. \
             Skipping one for being slow or flaky is a quarantine, and a quarantine \
             nobody can see the end of is how a lane shrinks back.\nStated reason: {reason}"
        );
    }

    // And the other direction: a roster row for a test the lane does NOT subtract is a
    // row nobody owes. (`the_unrun_ignored_test_roster_carries_no_stale_rows` catches
    // the case where the lane runs it; this catches the case where it is not a live
    // smoke at all any more.)
    for (name, reason) in IGNORED_TESTS_OUTSIDE_THE_LANE {
        assert!(
            excluded.contains(*name),
            "IGNORED_TESTS_OUTSIDE_THE_LANE claims `{name}`, but `just smoke-no-budget` \
             does not subtract it. The subtraction is the ONLY way a live \
             smoke goes unrun, so this row describes a world that no longer exists.\n\
             Its stated reason was: {reason}"
        );
    }
}

/// The test-granular rule REDS on an unrun ignored test and GREENS when the lane's
/// filter reaches it — exercised on synthetic input, so the counterfactual is part
/// of the suite rather than an edit somebody once made by hand.
#[test]
fn the_test_granular_rule_names_an_unrun_test_and_clears_when_the_filter_reaches_it() {
    let ignored: BTreeMap<String, Vec<String>> = [(
        "smokes".to_string(),
        vec![
            "smoke_shell_hermetic_env_scrubbed".to_string(),
            "smoke_main_local_socket_worker_dispatches_a_ping".to_string(),
        ],
    )]
    .into_iter()
    .collect();
    let declared = BTreeSet::new();

    let lane = |selection: LaneSelection| -> BTreeMap<String, Vec<LaneSelection>> {
        [("smokes".to_string(), vec![selection])]
            .into_iter()
            .collect()
    };
    let include = |filter: &str| LaneSelection {
        include: [filter.to_string()].into_iter().collect(),
        ..LaneSelection::default()
    };

    // RED: the lane narrows to `shell_`, so the local-socket smoke is unrun — the shape
    // the check was built to catch.
    let narrowed = lane(include("shell_"));
    let violations = unrun_ignored_tests(&ignored, &narrowed, &declared);
    assert_eq!(
        violations.len(),
        1,
        "a test the filter cannot reach must be named: {violations:?}"
    );
    assert!(violations[0].contains("smoke_main_local_socket_worker_dispatches_a_ping"));

    // GREEN: an unnarrowed lane (`just smoke` with no argument) runs everything.
    let unnarrowed = lane(include(""));
    assert!(
        unrun_ignored_tests(&ignored, &unnarrowed, &declared).is_empty(),
        "an empty filter means the binary is run in full"
    );

    // RED AGAIN, BY SUBTRACTION — the lane's real shape. Unnarrowed include, one
    // `not test(...)`: the excluded test is unrun even though nothing narrows the
    // binary. An implementation that skipped any binary with an unnarrowed include
    // would report this exact lane as fully covered.
    let subtracted = lane(LaneSelection {
        include: [String::new()].into_iter().collect(),
        exclude: ["smoke_workspace_ro_outputs".to_string()]
            .into_iter()
            .collect(),
        ..LaneSelection::default()
    });
    let mut with_paid = ignored.clone();
    with_paid
        .get_mut("smokes")
        .expect("the synthetic binary is named `smokes`")
        .push("smoke_workspace_ro_outputs".to_string());
    let violations = unrun_ignored_tests(&with_paid, &subtracted, &declared);
    assert_eq!(
        violations.len(),
        1,
        "a subtracted test must be reported unrun: {violations:?}"
    );
    assert!(
        violations[0].contains("smoke_workspace_ro_outputs"),
        "the failure must NAME the subtracted test: {violations:?}"
    );
    // …and the subtraction must not spill onto its neighbours.
    assert!(
        !violations[0].contains("smoke_shell_hermetic_env_scrubbed"),
        "a `not test(...)` clause must subtract only what it names: {violations:?}"
    );

    // GREEN: or the row declares who runs it instead.
    let declared_row: BTreeSet<String> =
        ["smoke_main_local_socket_worker_dispatches_a_ping".to_string()]
            .into_iter()
            .collect();
    assert!(
        unrun_ignored_tests(&ignored, &narrowed, &declared_row).is_empty(),
        "declaring the test's real runner must clear the violation"
    );
}

/// The attribute scan pairs an `#[ignore]` with the test it actually decorates.
///
/// Both directions, because either one alone is satisfiable by a broken scanner: a
/// matcher that fired on prose would report tests that do not exist, and one that
/// missed `#[tokio::test]`'s `async fn` would report a clean lane over 16 tests it
/// never saw.
#[test]
fn the_ignore_attribute_scan_pairs_the_attribute_with_its_test() {
    let source = "\
#[kata_test_utils::kata_timeout(secs = 60)]
#[tokio::test]
#[ignore = \"live binary smoke; KATA_LIVE_SMOKE=1 just smoke smoke_a\"]
async fn smoke_a() {}

/// prose that mentions #[ignore] in a doc comment
#[test]
fn not_ignored() {}

#[test]
#[ignore]
fn plain_b() {}
";
    assert_eq!(
        ignored_test_names(source),
        vec!["smoke_a".to_string(), "plain_b".to_string()],
        "the scan must pair each `#[ignore]` with the next fn (async or not) and must not \
         fire on prose"
    );
}

/// The justfile runs plain `cargo test` for DOCTESTS and nothing else.
///
/// THE DEFECT THIS PINS. `gen-types` ran
/// `cargo test -p kata-types export_bindings -- --ignored` behind a six-line
/// comment asserting, present tense, that the ts-rs binding export "writes
/// generated TypeScript to disk and must run to completion even if flagged
/// `#[ignore]`". No `export_bindings` test existed, no `ts-rs` was in
/// `Cargo.lock`, `crates/types/` carried no `#[ignore]` at all, and libtest exits
/// 0 when a filter selects nothing — so the recipe's entire discharge was an exit
/// code that could not distinguish work from ZERO TESTS SELECTED. `just
/// dev-loop-check` cannot see it (it proves recipes NAMED BY the routing table
/// exist, never that a recipe has a caller), and nothing else reads recipes with
/// no caller.
///
/// AGENTS.md's rule — never bare `cargo test`; the doctests behind `just test-doc` are
/// the one exception — is prose. This is that rule, executed.
#[test]
fn the_justfile_runs_cargo_test_only_for_doctests() {
    let justfile = justfile_text();

    let mut offenders = Vec::new();
    let mut doctest_lines = 0usize;
    for (number, line) in justfile.source.lines().enumerate() {
        let trimmed = line.trim();
        // Comments and prose are exempt: this file explains the rule in several
        // places, and a guard that fired on its own rationale would be deleted.
        if trimmed.starts_with('#') || !trimmed.starts_with("cargo test") {
            continue;
        }
        if trimmed.starts_with("cargo test --doc") {
            doctest_lines += 1;
            continue;
        }
        offenders.push(format!("  justfile:{}: {trimmed}", number + 1));
    }

    assert_eq!(
        doctest_lines, 1,
        "expected exactly ONE `cargo test --doc` line (the `test-doc` recipe); found \
         {doctest_lines}. Either the doctest recipe moved or this scan stopped reading \
         the justfile, and a ban that matches nothing bans nothing"
    );
    assert!(
        offenders.is_empty(),
        "{} justfile recipe line(s) run plain `cargo test`:\n{}\n\n\
         `cargo test` ignores `.config/nextest.toml`'s slow-timeouts, and a filter that \
         selects nothing exits 0 — indistinguishable from work performed, which is how \
         `gen-types` survived a deleted TypeScript surface. Use `just test` / \
         `just test-crate` / `just test-one`; doctests are the one exception.",
        offenders.len(),
        offenders.join("\n"),
    );
}

/// Neither required tier may boot a config that needs a model CLI.
///
/// The gate's closing banner and `just host-check` both say neither tier needs a model
/// CLI, and a verbatim boot would make that FALSE. `footprint-check` is the
/// only step in either tier that boots an installed main — the PUSH tier's — and
/// booting `config/kata.example.toml` verbatim would depend on host facts.
/// That file declares model-agent entries, and under the `oci` route a spawned
/// product has no business booting more agent config than the step exercises:
/// the measurement is a binary size and a boot RSS. The deriver strips every
/// entry but `[agents.shell]` and injects the `[node] environment` a boot
/// needs — the example declares none, so a verbatim boot is refused
/// `node_environment_undeclared` before it measures anything.
///
/// The artifact is PARSED rather than grepped, so "it still says `shell`
/// somewhere" cannot pass for "shell is the only agent".
///
/// COUNTERFACTUALS: drop the `awk` arm from `scripts/footprint-config.sh` and
/// assertion 2 names `default`, `gate`, `reviewer`; make the strip too
/// greedy and `agents` is empty — a spawn against that boot is the same defect,
/// an `[agents]` table that declares less than the example is a config the
/// gate did not derive; point the recipe back at `config/kata.example.toml`
/// and assertion 4 names the recipe.
#[test]
fn the_gate_boots_no_config_that_needs_a_model_cli() {
    let root = repo_root();
    let tmp = tempfile::tempdir().expect("tempdir");
    let data_dir = tmp.path().join("data");
    let jj_repo = tmp.path().join("repo");

    let output = std::process::Command::new("bash")
        .arg("scripts/footprint-config.sh")
        .arg(&data_dir)
        .arg("18400")
        .arg("19400")
        .arg(&jj_repo)
        .current_dir(&root)
        .output()
        .expect("running scripts/footprint-config.sh");
    assert!(
        output.status.success(),
        "scripts/footprint-config.sh failed: {}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = String::from_utf8(output.stdout).expect("derived config is UTF-8");
    assert!(!rendered.is_empty(), "derived config is empty");

    let config: toml::Value = toml::from_str(&rendered)
        .unwrap_or_else(|e| panic!("derived config is not valid TOML: {e}\n{rendered}"));

    // (2) Exactly one agent, and it is the shell agent.
    let agents = config
        .get("agents")
        .and_then(toml::Value::as_table)
        .expect("derived config must declare an [agents] table");
    let names: Vec<&str> = agents.keys().map(String::as_str).collect();
    assert_eq!(
        names,
        vec!["shell"],
        "the gate's only product boot must declare EXACTLY [agents.shell]. The \
         footprint step measures a binary size and a boot RSS, and a config \
         declaring model agents is more than that step exercises — an EMPTY \
         table is the same defect, a config the gate did not derive."
    );
    // The label decides the backend, and the shell route takes no key: an
    // `[agents.shell]` that declares any is refused at load
    // (`shell_agent_block_keys`), so the boot would never reach the measurement.
    assert_eq!(
        agents
            .get("shell")
            .and_then(toml::Value::as_table)
            .map(toml::Table::len),
        Some(0),
        "[agents.shell] must be the empty shell route block"
    );

    // (3) NON-VACUITY: a strip that gutted the file would satisfy (2) while
    // measuring a shape nobody ships. The RSS floor watches exactly these.
    for table in ["runtime", "workers", "api", "containment"] {
        assert!(
            config.get(table).and_then(toml::Value::as_table).is_some(),
            "derived config lost [{table}] — the footprint floors measure that shape, \
             so a config stripped down to [agents.shell] would pass the agent check \
             while measuring nothing the product ships:\n{rendered}"
        );
    }
    assert_eq!(
        config
            .get("telemetry")
            .and_then(|t| t.get("export"))
            .and_then(toml::Value::as_str),
        Some("prometheus"),
        "derived config lost the prometheus recorder, which is part of the measured shape"
    );

    // (4) The recipe actually uses it, and refuses BEFORE it boots.
    let justfile = justfile_text();
    let body = recipe_body(&justfile, "footprint-check").expect("`footprint-check` exists");
    assert!(
        body.contains("scripts/footprint-config.sh"),
        "`footprint-check` must derive its config through scripts/footprint-config.sh \
         rather than sed the example config inline; body:\n{body}"
    );
    let derive = body
        .lines()
        .position(|line| line.contains("scripts/footprint-config.sh"))
        .expect("`footprint-check` must derive its config");
    let boot = body
        .lines()
        .position(|line| line.contains("serve --config"))
        .expect("`footprint-check` must boot a main");
    assert!(
        derive < boot,
        "the derivation (line {derive}) must run BEFORE the boot (line {boot}); the script \
         refuses on its own exit code and `set -e` makes that fatal, so a bad derivation \
         fails there — naming the key it could not patch — instead of 180s later as a \
         ready-timeout that names the node. Body:\n{body}"
    );
    // The recipe must NOT re-implement the script's predicate. It once checked
    // the agent table itself with `grep -E '^\[agents\.'`: a line-oriented
    // equality where the script does a TOML parse. Two predicates over one
    // artifact disagree on an `[agents.shell.env]` sub-table (grep sees two
    // lines and fails, the parse sees one key and passes) and on an inline
    // `agents.shell = {}` (grep finds nothing and fails, the
    // parse passes). They agreed only by accident.
    // Comment lines are excluded because a comment is not a predicate — the
    // recipe EXPLAINS the grep it no longer runs, and a scan that cannot tell
    // the explanation from the code fires on the fix for the defect it names.
    let re_checks = body
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .any(|line| line.contains("grep -E '^\\[agents\\."));
    assert!(
        !re_checks,
        "`footprint-check` must trust scripts/footprint-config.sh's exit code rather than \
         re-checking the agent table with a line-oriented grep — that is a SECOND predicate \
         over one artifact and it disagrees with the script's TOML parse on sub-tables and \
         on inline tables. Body:\n{body}"
    );

    // ── (5) …and neither does any other gate-reachable spawn of the product ──
    //
    // Everything above proves ONE recipe. A plain non-`#[ignore]`d `#[test]` inside
    // `just test` that resolves a `config/*.toml` and spawns the REAL product against
    // it makes `just gate` depend on facts that config cannot supply — the host CLIs
    // it declares, and the `[node] environment` it does not — while the gate's
    // closing banner and `just host-check` say it needs neither. So every
    // gate-reachable spawn of the product is classified against the configs here.
    let configs = repo_configs();
    assert!(
        !configs.is_empty(),
        "no `config/*.toml` was found to classify — a scan that matches nothing proves nothing"
    );
    let needs_cli: BTreeSet<String> = configs
        .iter()
        .filter(|(_, text)| config_needs_a_model_cli(text))
        .map(|(name, _)| name.clone())
        .collect();

    let guard = this_guard_file();
    let mut sources: BTreeMap<PathBuf, String> = BTreeMap::new();
    // Every root, two crates' `smokes.rs` both (this scan wants files, not the
    // stem nextest's `binary(...)` matches), and each FILE of a binary on its own,
    // the suites folded into it included: a spawn and the config it boots sit in
    // one file, so text joined across a binary's files would pair one suite's
    // spawn with another suite's parse-only config.
    for path in workspace_test_roots() {
        if path == guard {
            continue;
        }
        for file in binary_files(&path) {
            let Ok(text) = std::fs::read_to_string(root.join(&file)) else {
                continue;
            };
            sources.insert(file, text);
        }
    }
    assert!(
        sources.len() > 20,
        "only {} test-binary sources were read — the scan is not reaching the workspace",
        sources.len()
    );

    let offenders = model_cli_spawn_offenders(&sources, &needs_cli);
    assert!(
        offenders.is_empty(),
        "{} gate-reachable test target(s) spawn the product against a config that needs a \
         model CLI:\n{}\n\n\
         A gate-reachable spawn must boot only the config the deriver emitted: \
         the example config declares model-agent entries and no `[node] \
         environment`, so a spawn against it couples the gate to facts it \
         cannot supply — the assertion is never reached. `just gate` is \
         HOST-INDEPENDENT BY CONSTRUCTION and `just host-check` tells \
         operators so in seconds; a test like this makes that promise false. \
         Fix: derive a shell-only config with the one deriver, \
         `scripts/footprint-config.sh`, instead of pointing at the example config.",
        offenders.len(),
        offenders.join("\n"),
    );
}

/// A source config with everything the deriver touches, plus the two shapes an
/// exact-header strip gets wrong: a SUB-TABLE of the shell agent (kept, as
/// `[agents.shell.<sub>]`), and a non-shell agent with a sub-table of its own.
const DERIVER_FIXTURE: &str = r#"
[node]
data_dir = "~/.kata/data"

[api]
bind = "127.0.0.1:8400"

[agents.shell]

[agents.shell.env]
FOO = "bar"

[agents.coder]
adapter = "nanocode_openai"

[agents.coder.limits]
max = 1

[vcs]
jj_repo = ".."

[telemetry]
export = "prometheus"
metrics_bind  = "127.0.0.1:9400"
"#;

/// Run `scripts/footprint-config.sh` over a fixture. Returns (status, stdout, stderr).
fn derive(fixture: &str, dir: &Path) -> (bool, String, String) {
    derive_through(
        &repo_root().join("scripts/footprint-config.sh"),
        fixture,
        dir,
    )
}

/// Run a copy of the deriver at `script` over a fixture, as [`derive`] does.
fn derive_through(script: &Path, fixture: &str, dir: &Path) -> (bool, String, String) {
    let source = dir.join("source.toml");
    std::fs::write(&source, fixture).expect("write deriver fixture");
    let output = std::process::Command::new("bash")
        .arg(script)
        .arg(dir.join("data"))
        .arg("18400")
        .arg("19400")
        .arg(dir.join("repo"))
        .arg(&source)
        .current_dir(repo_root())
        .output()
        .expect("running scripts/footprint-config.sh");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The deriver must FAIL LOUDLY when a substitution matches nothing, and must
/// keep the shell agent's sub-tables.
///
/// Both halves are the defect this script exists to delete, reintroduced inside
/// it. It patched four keys with literal `sed` expressions and asserted nothing
/// about whether any applied. Only `bind` had a loud failure mode (the recipe
/// polls the port). Reformat `data_dir = "~/.kata/data"` to
/// `data_dir="~/.kata/data"`, bump the metrics port off 9400, or change
/// `jj_repo` off `".."` — all ordinary edits to a 300-line commented example —
/// and `sed` matched nothing, exited 0, and the caller booted a main pointed at
/// the operator's live `~/.kata/data`, binding the host's 9400,
/// op-log-GC-sweeping whatever `.jj` sat beside the config.
///
/// The sub-table half: the strip was `$0 != "[agents.shell]"`, so every
/// `[agents.shell.<sub>]` was dropped WHILE BOTH GUARDS STAYED GREEN — one
/// `[agents.*]` line, one `agents` key — and the boot would have measured a
/// shell agent configured differently from the one the product ships. That is
/// exactly the silent drift the script's header claims deriving makes
/// impossible.
///
/// COUNTERFACTUALS: restore `$0 != "[agents.shell]"` in the awk arm and the
/// `[agents.shell.env]` assertion goes red; delete the python verification
/// block and all three refusal arms go red (each derives a config that still
/// points at host state, and exits 0).
#[test]
fn the_deriver_refuses_a_substitution_that_matched_nothing_and_keeps_shell_subtables() {
    let tmp = tempfile::tempdir().expect("tempdir");

    // (1) The happy path: the shell agent AND its sub-table survive; every
    // other agent, sub-tables included, is gone.
    let dir = tmp.path().join("ok");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let (ok, stdout, stderr) = derive(DERIVER_FIXTURE, &dir);
    assert!(ok, "deriving the fixture must succeed; stderr:\n{stderr}");
    let parsed: toml::Value = toml::from_str(&stdout)
        .unwrap_or_else(|e| panic!("derived config is not valid TOML: {e}\n{stdout}"));
    let agents = parsed
        .get("agents")
        .and_then(toml::Value::as_table)
        .expect("derived config declares [agents]");
    let names: Vec<&str> = agents.keys().map(String::as_str).collect();
    assert_eq!(
        names,
        vec!["shell"],
        "only the shell agent survives:\n{stdout}"
    );
    assert_eq!(
        agents
            .get("shell")
            .and_then(|shell| shell.get("env"))
            .and_then(|env| env.get("FOO"))
            .and_then(toml::Value::as_str),
        Some("bar"),
        "the shell agent's SUB-TABLE must survive the strip. Dropping it leaves exactly one \
         `[agents.*]` line and exactly one `agents` key, so every guard stays green while the \
         boot measures a shell agent configured differently from the one the product ships:\
         \n{stdout}"
    );
    assert!(
        !stdout.contains("coder"),
        "every non-shell agent, sub-tables included, must be gone:\n{stdout}"
    );

    // (2) Each silently-failing substitution is now a loud refusal that NAMES
    // the key. `bind` is omitted: it always had a loud failure mode.
    for (label, from, to) in [
        (
            "node.data_dir",
            "data_dir = \"~/.kata/data\"",
            "data_dir=\"~/.kata/data\"",
        ),
        (
            "telemetry.metrics_bind",
            "metrics_bind  = \"127.0.0.1:9400\"",
            "metrics_bind  = \"127.0.0.1:9500\"",
        ),
        ("vcs.jj_repo", "jj_repo = \"..\"", "jj_repo = \"../..\""),
    ] {
        let dir = tmp.path().join(label);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let mutated = DERIVER_FIXTURE.replace(from, to);
        assert_ne!(mutated, DERIVER_FIXTURE, "the {label} mutation must apply");
        let (ok, stdout, stderr) = derive(&mutated, &dir);
        assert!(
            !ok,
            "an ordinary edit to `{from}` makes the {label} substitution match NOTHING; the \
             deriver must refuse rather than emit a config still pointing at host state. \
             stdout:\n{stdout}"
        );
        assert!(
            stderr.contains(label),
            "the refusal must NAME the key that did not apply, or the operator gets a boot \
             failure three steps downstream. stderr:\n{stderr}"
        );
        assert!(
            stdout.trim().is_empty(),
            "a refusing deriver must emit no config at all; stdout:\n{stdout}"
        );
    }
}

/// The deriver's `[node] environment` and `[agents]` read-back arms each PRINT
/// their refusal.
///
/// The arms compare the declaration read back out of the derived TOML with the
/// closure the script emitted, so no source config reaches them: the script
/// inserts the declaration itself. They fire only when the script's own
/// `environment_block` and its read-back disagree, so this cell drives a copy of
/// the script with that block edited (or, for the absent arm, not inserted), once
/// per arm. Each run must refuse, emit no config, and name the key on stderr; an
/// arm whose message cannot be formatted
/// (a quoting slip inside the script's single-quoted `python3 -c` body reads as an
/// undefined name) still exits non-zero but prints a traceback instead. The agent
/// arm is reachable from a source config, so it runs over the fixture with its
/// shell agent renamed away.
#[test]
fn the_deriver_prints_each_read_back_refusal_by_name() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let script = std::fs::read_to_string(repo_root().join("scripts/footprint-config.sh"))
        .expect("read scripts/footprint-config.sh");
    for (label, from, to) in [
        (
            "node.environment.store_paths",
            r#"store_paths = [\"$busybox\"]"#,
            r#"store_paths = [\"$busybox-elsewhere\"]"#,
        ),
        (
            "node.environment.path_prepend",
            r#"path_prepend = [\"$busybox/bin\"]"#,
            r#"path_prepend = [\"$busybox/sbin\"]"#,
        ),
    ] {
        let dir = tmp.path().join(label);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let mutated = script.replace(from, to);
        assert_ne!(mutated, script, "the {label} edit must apply to the script");
        let copy = dir.join("footprint-config.sh");
        std::fs::write(&copy, mutated).expect("write the edited deriver");
        let (ok, stdout, stderr) = derive_through(&copy, DERIVER_FIXTURE, &dir);
        assert!(
            !ok,
            "a declaration that disagrees with the emitted closure must be refused; \
             stdout:\n{stdout}"
        );
        assert!(
            stdout.trim().is_empty(),
            "a refusing deriver must emit no config at all; stdout:\n{stdout}"
        );
        assert!(
            stderr.contains(&format!("{label} = ")) && stderr.contains("expected ["),
            "the refusal must name `{label}` with the value it read and the one it \
             expected; stderr:\n{stderr}"
        );
        assert!(
            !stderr.contains("Traceback"),
            "the refusal must print its own message, not a Python traceback; \
             stderr:\n{stderr}"
        );
    }

    // The absent arm: the script inserts no declaration at all.
    let dir = tmp.path().join("node.environment");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let mutated = script.replace(r"|&\n$environment_block|", "|&|");
    assert_ne!(
        mutated, script,
        "the insertion edit must apply to the script"
    );
    let copy = dir.join("footprint-config.sh");
    std::fs::write(&copy, mutated).expect("write the edited deriver");
    let (ok, stdout, stderr) = derive_through(&copy, DERIVER_FIXTURE, &dir);
    assert!(
        !ok && stdout.trim().is_empty(),
        "a derived config with no `[node] environment` must be refused with no config \
         emitted; stdout:\n{stdout}"
    );
    assert!(
        stderr.contains("node.environment is absent") && !stderr.contains("Traceback"),
        "the refusal must name the missing declaration; stderr:\n{stderr}"
    );

    // The agent-table arm is reachable from a source config: one with no shell agent.
    let dir = tmp.path().join("agents");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let no_shell = DERIVER_FIXTURE.replace("[agents.shell", "[agents.other");
    assert_ne!(no_shell, DERIVER_FIXTURE, "the shell-agent edit must apply");
    let (ok, stdout, stderr) = derive(&no_shell, &dir);
    assert!(
        !ok && stdout.trim().is_empty(),
        "a config with no shell agent must be refused with no config emitted; \
         stdout:\n{stdout}"
    );
    assert!(
        stderr.contains("[agents] declares") && !stderr.contains("Traceback"),
        "the refusal must name the agent table; stderr:\n{stderr}"
    );
}

/// Every `config/*.toml` in the repo, as (file name, text).
fn repo_configs() -> BTreeMap<String, String> {
    let dir = repo_root().join("config");
    let mut out = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension() != Some(OsStr::new("toml")) || !path.is_file() {
            continue;
        }
        let (Some(name), Ok(text)) = (
            path.file_name().and_then(OsStr::to_str),
            std::fs::read_to_string(&path),
        ) else {
            continue;
        };
        out.insert(name.to_string(), text);
    }
    out
}

/// Does this config declare agent entries a gate spawn should not boot?
///
/// PARSED, not grepped: "it mentions shell somewhere" is not "shell is the only
/// agent". The LABEL decides an entry's backend (`deserialize_agents` in
/// `crates/types/src/config.rs`): every label but the reserved deterministic ones
/// is a model agent. An ABSENT or EMPTY `[agents]` table counts as needing one —
/// a spawn against a config the deriver did not emit is the same defect.
fn config_needs_a_model_cli(text: &str) -> bool {
    let Ok(parsed) = toml::from_str::<toml::Value>(text) else {
        // Unparseable configs are not this guard's business; other tests own them.
        return false;
    };
    let Some(agents) = parsed.get("agents").and_then(toml::Value::as_table) else {
        return true;
    };
    if agents.is_empty() {
        return true;
    }
    agents
        .keys()
        .any(|label| !DETERMINISTIC_AGENT_LABELS.contains(&label.as_str()))
}

/// The reserved labels whose `[agents.<label>]` entry is the shell route, which
/// spawns no model (`kata_types::agent::is_deterministic_agent_label`).
const DETERMINISTIC_AGENT_LABELS: &[&str] = &["shell", "workspace_effect"];

/// Does this test target SPAWN the product?
///
/// `CARGO_BIN_EXE_<name>` is the mechanism — cargo defines it only for
/// integration test targets, which is why this scan covers `tests/` and not
/// `src/` unit tests. The two `spawn_*` prefixes cover every `NodeHandle`
/// constructor in `kata_test_utils::live`; a file that merely RENDERS a config
/// (`crates/test-utils/tests/live_tests.rs`) calls none of them and is
/// correctly not a spawner.
fn spawns_the_product(source: &str) -> bool {
    source
        .lines()
        .map(str::trim_start)
        .filter(|line| !line.starts_with("//"))
        .any(|line| {
            line.contains("CARGO_BIN_EXE_")
                || line.contains("spawn_supervised_main")
                || line.contains("spawn_main_with_local_socket")
        })
}

/// Does this source point a spawn at a config that needs a model CLI, and if so
/// why?
///
/// Two ways in: naming one of the repo configs that needs one, or declaring a
/// model agent inline — an `[agents.<label>]` header under a label no reserved
/// deterministic one — in a config the test writes itself.
///
/// BOTH predicates read CODE lines only. A comment is not a spawn, and this
/// workspace explains itself constantly: a doc comment that names
/// `config/kata.example.toml` and quotes `[agents.default]` for the sole purpose of
/// recording why a spawn must not boot either is not a spawn. A scan that cannot
/// tell an explanation from a spawn makes the correct comment unwritable.
fn model_cli_config_reasons(source: &str, needs_cli: &BTreeSet<String>) -> Vec<String> {
    let code: Vec<&str> = source
        .lines()
        .map(str::trim_start)
        .filter(|line| !line.starts_with("//"))
        .collect();

    let mut reasons = Vec::new();
    for name in needs_cli {
        if code.iter().any(|line| line.contains(name.as_str())) {
            reasons.push(format!("names `config/{name}`, which needs a model CLI"));
        }
    }
    for trimmed in &code {
        let Some(rest) = trimmed.strip_prefix("[agents.") else {
            continue;
        };
        let label = rest.split(['.', ']']).next().unwrap_or_default();
        if !label.is_empty() && !DETERMINISTIC_AGENT_LABELS.contains(&label) {
            reasons.push(format!("declares an inline `[agents.{label}]` model agent"));
            break;
        }
    }
    reasons
}

/// Does this source carry at least one test that `just test` will RUN?
///
/// `#[ignore]`d tests are a different lane — the containment lane runs them with
/// `--run-ignored all`, and the guards above this one own that. Attributes are
/// collected per preceding block so BOTH orderings (`#[test]` above `#[ignore]`
/// and below it) classify the same.
fn has_a_gate_reachable_test(source: &str) -> bool {
    let mut attrs: Vec<&str> = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#[") {
            attrs.push(trimmed);
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }
        let after_pub = trimmed.strip_prefix("pub ").unwrap_or(trimmed);
        let after_async = after_pub.strip_prefix("async ").unwrap_or(after_pub);
        if after_async.starts_with("fn ") {
            let is_test = attrs.iter().any(|attr| {
                attr.starts_with("#[test]")
                    || attr.starts_with("#[tokio::test")
                    || attr.starts_with("#[rstest")
            });
            let ignored = attrs.iter().any(|attr| attr.starts_with("#[ignore"));
            if is_test && !ignored {
                return true;
            }
        }
        attrs.clear();
    }
    false
}

/// Gate-reachable test targets that spawn the product against a model-CLI
/// config.
///
/// Pure over its inputs so the counterfactual runs on synthetic sources rather
/// than by editing a real test and hoping it gets restored.
fn model_cli_spawn_offenders(
    sources: &BTreeMap<PathBuf, String>,
    needs_cli: &BTreeSet<String>,
) -> Vec<String> {
    let mut offenders = Vec::new();
    for (path, source) in sources {
        if !spawns_the_product(source) || !has_a_gate_reachable_test(source) {
            continue;
        }
        let reasons = model_cli_config_reasons(source, needs_cli);
        if reasons.is_empty() {
            continue;
        }
        offenders.push(format!("  {} — {}", path.display(), reasons.join("; ")));
    }
    offenders
}

/// COUNTERFACTUAL for the rule above, on synthetic sources: it names a
/// gate-reachable spawn of a model-CLI config, and clears when the same file
/// derives a shell-only one.
///
/// The three negative rows are the ones that make the rule usable rather than a
/// blanket ban: a spawn of a shell-only config, an `#[ignore]`d spawn (the
/// containment lane's business, not the gate's), and a file that merely PARSES
/// the example config without spawning anything — which is what the other eight
/// `config/kata.example.toml` consumers in this workspace do.
#[test]
fn the_model_cli_spawn_rule_names_an_offender_and_clears_when_it_is_fixed() {
    let needs_cli: BTreeSet<String> = ["kata.example.toml".to_string()].into_iter().collect();

    let offending = r#"
        fn cfg() -> PathBuf { repo_root().join("config/kata.example.toml") }
        #[test]
        fn spawns() { Command::new(env!("CARGO_BIN_EXE_kata")).arg("run").output(); }
    "#;
    let fixed = r#"
        fn cfg() -> PathBuf { derive_with("scripts/footprint-config.sh") }
        #[test]
        fn spawns() { Command::new(env!("CARGO_BIN_EXE_kata")).arg("run").output(); }
    "#;
    let ignored = r#"
        fn cfg() -> PathBuf { repo_root().join("config/kata.example.toml") }
        #[test]
        #[ignore = "live smoke: containment lane runs it with --run-ignored all"]
        fn spawns() { Command::new(env!("CARGO_BIN_EXE_kata")).arg("run").output(); }
    "#;
    let parses_only = r#"
        /// Reads the example config. Mentions `[agents.default]` in prose only.
        #[test]
        fn parses() { ConfigManager::load(&repo_root().join("config/kata.example.toml")); }
    "#;
    let inline_model_agent = r##"
        const CFG: &str = r#"
[agents.default]
adapter = "nanocode_openai"
"#;
        #[test]
        fn spawns() { Command::new(env!("CARGO_BIN_EXE_kata")).arg("serve").output(); }
    "##;

    let mut sources = BTreeMap::new();
    sources.insert(
        PathBuf::from("crates/x/tests/offending.rs"),
        offending.into(),
    );
    sources.insert(PathBuf::from("crates/x/tests/ignored.rs"), ignored.into());
    sources.insert(
        PathBuf::from("crates/x/tests/parses_only.rs"),
        parses_only.into(),
    );

    let named = model_cli_spawn_offenders(&sources, &needs_cli);
    assert_eq!(
        named.len(),
        1,
        "exactly the spawning, gate-reachable file must be named; got {named:?}"
    );
    assert!(
        named[0].contains("offending.rs") && named[0].contains("kata.example.toml"),
        "the finding must name the file AND why: {named:?}"
    );

    sources.insert(PathBuf::from("crates/x/tests/offending.rs"), fixed.into());
    assert!(
        model_cli_spawn_offenders(&sources, &needs_cli).is_empty(),
        "deriving a shell-only config must clear the finding"
    );

    // The inline arm is the half a path scan cannot see: a test that writes its
    // OWN `kata.toml` with a CLI-backed agent and boots it is the same defect.
    sources.insert(
        PathBuf::from("crates/x/tests/inline.rs"),
        inline_model_agent.into(),
    );
    let inline = model_cli_spawn_offenders(&sources, &needs_cli);
    assert_eq!(
        inline.len(),
        1,
        "the inline declaration must be caught: {inline:?}"
    );
    assert!(inline[0].contains("inline.rs"), "{inline:?}");
}

/// COUNTERFACTUAL for [`config_needs_a_model_cli`]: parsed, not grepped, and an
/// empty or absent `[agents]` table is the SAME defect as a model agent — a
/// spawn against a config the deriver did not emit.
#[test]
fn a_config_needs_a_model_cli_unless_every_declared_agent_is_the_shell() {
    assert!(!config_needs_a_model_cli("[agents.shell]\n"));
    assert!(!config_needs_a_model_cli(
        "[agents.shell]\n[agents.workspace_effect]\n"
    ));
    assert!(config_needs_a_model_cli(
        "[agents.shell]\n[agents.default]\n"
    ));
    assert!(config_needs_a_model_cli("[agents]\n"), "empty table");
    assert!(
        config_needs_a_model_cli("[node]\ndata_dir = \"/tmp\"\n"),
        "absent table"
    );
    // A comment naming the shell agent is not a declaration of one.
    assert!(config_needs_a_model_cli(
        "# [agents.shell]\n[agents.coder]\nadapter = \"nanocode_openai\"\n"
    ));
}

/// `oci-live-smoke` BUILDS the static `kata-toolhost` its toolhost-capsule cells
/// provision, before the run that selects them.
///
/// Every binary that includes the shared rig (`crates/worker/tests/common/
/// toolhost_capsule.rs`, today `toolhost_live` and `nanocode_capsule_live`) reads the
/// musl build from the target directory (the rig's `TOOLHOST_TARGET`), and a nextest
/// run builds test binaries, never a `--target` build of another package. So
/// without this step the cells read whatever musl build an earlier command left:
/// a stale one fails each cell's `Hello` check, and none at all panics them, or,
/// worse, a stale toolhost from the SAME source digest passes. The expected
/// command is derived from the rig's own constant (its triple and profile), and the
/// binaries from the workspace's test targets that include the rig, so neither can
/// drift apart from the recipe silently. A test target includes the rig when its
/// root file carries a `#[path = "…"]` attribute whose target, resolved against that
/// file's directory and normalised lexically, is the rig (`./common/…` and a path
/// through `..` are the rig too); a `mod` declared inside another module file is not
/// read.
///
/// COUNTERFACTUAL: delete the `cargo build -p kata-toolhost --target …` line from
/// `oci-live-smoke`, move it below the selection, drop a rig binary from the
/// selection (however its `#[path]` spells the rig), or change the rig's profile
/// without the recipe's, and this names the recipe.
#[test]
fn the_oci_live_smoke_builds_the_static_toolhost_its_live_cells_read() {
    const RIG: &str = "crates/worker/tests/common/toolhost_capsule.rs";
    let rig_path = repo_root().join(RIG);
    let rig = std::fs::read_to_string(&rig_path)
        .unwrap_or_else(|error| panic!("{} reads: {error}", rig_path.display()));
    let target = rig
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("pub const TOOLHOST_TARGET: &str = \"")?
                .strip_suffix("\";")
        })
        .unwrap_or_else(|| {
            panic!(
                "{} no longer declares `pub const TOOLHOST_TARGET: &str = \"<triple>/<profile>/\
                 kata-toolhost\";`, which this guard derives the build from",
                rig_path.display()
            )
        });
    let [triple, profile, program] = target.split('/').collect::<Vec<_>>()[..] else {
        panic!("TOOLHOST_TARGET is not <triple>/<profile>/<program>: {target}");
    };
    assert_eq!(program, "kata-toolhost", "TOOLHOST_TARGET: {target}");
    let profile_flag = match profile {
        "debug" => "",
        "release" => " --release",
        other => panic!("TOOLHOST_TARGET names the profile {other:?}, not debug or release"),
    };
    let command =
        format!("cargo build -p kata-toolhost --target {triple}{profile_flag} || exit $?");

    let readers: Vec<String> = workspace_test_binaries()
        .into_iter()
        .filter(|(_, path)| module_files(path).contains(Path::new(RIG)))
        .map(|(name, _)| name)
        .collect();
    assert!(
        readers.contains(&"toolhost_live".to_owned()),
        "no test binary includes {RIG} but {readers:?}: the scan for its readers is broken"
    );

    let justfile = justfile_text();
    let body = body_with_calls(&justfile, "oci-live-smoke").expect("`oci-live-smoke` exists");
    let built = line_index(&body, &command).unwrap_or_else(|| {
        panic!(
            "`oci-live-smoke` runs {readers:?}, which read {target} under the target directory, \
             but has no line `{command}`: the cells would read a stale build or none. \
             Body:\n{body}"
        )
    });
    for reader in &readers {
        let selected = body
            .lines()
            .position(|line| line.contains(&format!("binary({reader})")))
            .unwrap_or_else(|| {
                panic!(
                    "`{reader}` includes {RIG}, and `oci-live-smoke` does not select \
                     binary({reader}). Body:\n{body}"
                )
            });
        assert!(
            built < selected,
            "`oci-live-smoke` builds the static toolhost (line {built}) only after the \
             selection that runs `{reader}` (line {selected}). Body:\n{body}"
        );
    }
}

/// COUNTERFACTUALS for the recipe rule ([`read_gates`]) and for Just's linewise join
/// ([`body_lines`]): a recipe that names nextest holds nothing but canonical runs, in a
/// linewise recipe with no parameter and no attribute, and each line is judged as Just
/// joins it.
#[test]
fn a_recipe_that_names_nextest_holds_only_canonical_runs_as_just_joins_them() {
    const SKIP: &str = "-E 'binary(a)' -- --skip n";
    let mut failures = Vec::new();
    // Bodies, each refused.
    for body in [
        // Just joins a line on ANY trailing `\`, an even run included, and runs the
        // canonical text that follows as part of the line before it.
        ": \\\\\ncargo nextest run -E 'binary(a)'\n".to_owned(),
        "# a note \\\ncargo nextest run -E 'binary(a)'\n".to_owned(),
        // Just drops a continuation's leading blanks: this runs `cargo nextest run`.
        format!("cargo nex\\\n        test run {SKIP}\n"),
        // `--no-run` only as the exact `cargo nextest run --workspace --no-run`.
        "KATA_LIVE_SMOKE=1 cargo nextest run --workspace -P live-smoke --test-threads=1 --run-ignored all -E 'binary(a)' --no-run\n".to_owned(),
        "cargo nextest run --no-run --workspace\n".to_owned(),
        "cargo nextest run --no-run\n".to_owned(),
        "cargo nextest run --workspace --no-run -E 'binary(a)'\n".to_owned(),
        // `env -u` only for a name a gate unsets.
        "env -u KATA_LIVE_SMOKE cargo nextest run -E 'binary(a)'\n".to_owned(),
        "env -u KATA_SANDBOX_REQUIRE_LIVE cargo nextest run -E 'binary(a)'\n".to_owned(),
        "env -u KATA_X cargo nextest run -E 'binary(a)'\n".to_owned(),
        // Any other line in a recipe that names nextest: the run it holds is not read
        // as the run the shell starts.
        format!("cargo nextest run --workspace\n$c $s run {SKIP}\n"),
        format!("c=cargo; s=nextest; $c $s run {SKIP}\n"),
        "if false; then\ncargo nextest run -E 'binary(a)'\nfi\nc=cargo\n\"$c\" nex\"\"test run -E 'binary(a)' -- --skip n\n".to_owned(),
        "argv=(\ncargo nextest run -E 'binary(a)'\n)\n\"${argv[@]}\" -- --skip n\n".to_owned(),
        "bash <<'EOF'\ncargo nextest run -E 'binary(a)'\nEOF\n".to_owned(),
        "cargo nextest run -E 'binary(a)'\nbash <<< \"$line\"\n".to_owned(),
        "root=\"$(pwd)\"\nbin=\"$root/target/debug/kata\"\n$bin run x\ncargo nextest run --workspace\n".to_owned(),
        "set -euo pipefail\ncargo nextest run --workspace\n".to_owned(),
        "true\ncargo nextest run --workspace\n".to_owned(),
    ] {
        let read = read_gate_nextest(&body);
        if read.refusals.is_empty() {
            failures.push(format!("not refused: {body:?}"));
        }
    }
    // Read as Just runs them.
    for (body, text) in [
        (
            "cargo nex\\\n        test run -E 'binary(a)'\n",
            "cargo nextest run -E binary(a)",
        ),
        (
            "KATA_LIVE_SMOKE=1 \\\n\t  cargo nextest run --workspace \\\n    -E 'binary(a)'\n",
            "cargo nextest run --workspace -E binary(a)",
        ),
        (
            "cargo nextest run --workspace --no-run\n",
            "cargo nextest run --workspace --no-run",
        ),
        (
            "    cargo nextest run --workspace \\\n        --no-run\n",
            "cargo nextest run --workspace --no-run",
        ),
        (
            "env -u KATA_TEST_PUBLICATION_FAULT_MODE -u KATA_TEST_PUBLICATION_FAULT_ROOT cargo nextest run -E 'binary(a)'\n",
            "cargo nextest run -E binary(a)",
        ),
        (
            "env -u KATA_E3_AGENT -u KATA_E3_FUNDED -u KATA_E3_FORGE_CLONE cargo nextest run -E 'binary(a)'\n",
            "cargo nextest run -E binary(a)",
        ),
    ] {
        let read = read_gate_nextest(body);
        if !read.refusals.is_empty() || read.runs.iter().map(|run| run.text.as_str()).ne([text]) {
            failures.push(format!("{body:?}: {:?} {:?}", read.runs, read.refusals));
        }
    }
    // The join itself, not only the recipe rule: an even run of `\` still joins, so the
    // canonical text after it is no run of its own, and the refusal quotes the joined line.
    let read = read_gate_nextest(": \\\\\ncargo nextest run --workspace\n");
    if !read.runs.is_empty()
        || read
            .refusals
            .iter()
            .all(|refusal| !refusal.contains(": \\cargo nextest run --workspace"))
    {
        failures.push(format!(
            "`: \\\\` is not joined to the next line: {:?} {:?}",
            read.runs, read.refusals
        ));
    }
    // Recipes: one that names nextest is linewise, with no parameter and no attribute.
    for source in [
        "gate:\n    #!/usr/bin/env bash\n    cargo nextest run --workspace\n",
        "[script(\"bash\")]\ngate:\n    cargo nextest run --workspace\n",
        "[no-cd]\ngate:\n    cargo nextest run --workspace\n",
        "[private]\ngate:\n    cargo nextest run --workspace\n",
        "gate x=\"\":\n    cargo nextest run --workspace\n",
        "gate *args:\n    cargo nextest run --workspace\n",
        "gate:\n    just leaf\nleaf $CARGO_TARGET_DIR=\"t\":\n    cargo nextest run --workspace\n",
    ] {
        if read_gates(&parse_justfile_source(source), &["gate"])
            .refusals
            .is_empty()
        {
            failures.push(format!("not refused: {source:?}"));
        }
    }
    for source in [
        "gate: dep\n    cargo nextest run --workspace\ndep:\n    true\n",
        "[private]\ngate:\n    #!/usr/bin/env bash\n    set -euo pipefail\n    just _leaf\n_leaf:\n    cargo nextest run --workspace\n",
    ] {
        let read = read_gates(&parse_justfile_source(source), &["gate"]);
        if !read.refusals.is_empty() || read.runs.len() != 1 {
            failures.push(format!("{source:?}: {:?} {:?}", read.runs, read.refusals));
        }
    }
    assert!(
        failures.is_empty(),
        "{} failure(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}
