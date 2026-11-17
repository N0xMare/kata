//! The curated example-pack library under `workflows/examples/` is a
//! GATE-ENFORCED learning surface.
//!
//! Every `.star` there must LOAD-CHECK clean (compile through the checked IR
//! with NO verifier `Error`), the corpus must stay above a floor size, and
//! `MANIFEST.toml` (consumed by `kata init` seeding) must list exactly the
//! example files on disk. A broken example — one that fails to compile or trips
//! a hard verifier error — FAILS this test, so it cannot ride into the repo.
//!
//! This rides `just test` (hence `just gate`) as an ordinary nextest test.

use std::path::{Path, PathBuf};

use kata_program::execution_program::VerifierStatus;
use kata_program::preflight::build_workflow_compiled_artifact_from_file;

/// `<repo>` — the crate lives at `<repo>/crates/workflow`.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate lives under <repo>/crates/workflow")
        .to_path_buf()
}

fn examples_root() -> PathBuf {
    repo_root().join("workflows").join("examples")
}

/// Loader roots for compiling an example: the examples root itself (so an
/// example may `load()` a sibling) plus the two bundled stdlib roots (so an
/// example may `load("kata/std.star", ..)` / `load("kata/factory.star", ..)`).
fn loader_roots() -> Vec<PathBuf> {
    let wf = repo_root().join("workflows");
    vec![examples_root(), wf.join("std"), wf.join("kata-factory")]
}

/// Every `*.star` under `workflows/examples/`, recursively, sorted.
fn example_star_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_star(&examples_root(), &mut out);
    out.sort();
    out
}

fn collect_star(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("reading examples dir {}: {e}", dir.display()));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_star(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "star") {
            out.push(path);
        }
    }
}

/// Load-check a single example: compile it to checked IR and reject any hard
/// verifier `Error`. Returns `Err(reason)` describing the failure. This is the
/// EXACT gate predicate the corpus test and the fail-closed regression test both
/// run, so the guard cannot rot into a no-op.
fn load_check(path: &Path) -> Result<(), String> {
    let artifact = build_workflow_compiled_artifact_from_file(path, &loader_roots())
        .map_err(|e| format!("compile failed: {e}"))?;
    let verifier = &artifact.execution_program.verifier;
    if verifier.status == VerifierStatus::Error {
        let errors = verifier
            .diagnostics
            .iter()
            .filter(|d| d.severity == kata_program::execution_program::VerifierSeverity::Error)
            .map(|d| format!("[{}] {}", d.code, d.message))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!("verifier reported errors: {errors}"));
    }
    Ok(())
}

/// Every curated example loads clean — compiles and carries no verifier Error.
#[test]
fn every_example_loads_clean() {
    let files = example_star_files();
    assert!(
        !files.is_empty(),
        "workflows/examples/ must hold curated example workflows, found none"
    );

    let mut failures = Vec::new();
    for path in &files {
        if let Err(reason) = load_check(path) {
            failures.push(format!("{}: {reason}", path.display()));
        }
    }

    assert!(
        failures.is_empty(),
        "these curated examples do NOT load-check clean:\n  {}",
        failures.join("\n  ")
    );
}

/// Parse every `name = "..."` value from a `[[example]]` manifest. The manifest
/// is simple authored TOML, so a line scan (no toml dev-dep) suffices; the sync
/// test proves the `file` rows match disk, so the `name` rows are trustworthy.
fn manifest_names() -> Vec<String> {
    let manifest_path = examples_root().join("MANIFEST.toml");
    let manifest = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", manifest_path.display()));
    manifest
        .lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("name")?.trim_start();
            let rest = rest.strip_prefix('=')?.trim();
            let inner = rest.strip_prefix('"')?;
            let end = inner.find('"')?;
            Some(inner[..end].to_string())
        })
        .collect()
}

/// The corpus must carry EVERY mandated example, not merely N files — a
/// bare count floor would be satisfied by 11 copies of hello-workflow. This
/// asserts the mandated set (one per named category plus the minimal
/// hello-workflow) is present by name, so dropping any category FAILS the gate.
#[test]
fn example_corpus_meets_minimum_coverage() {
    // The mandated coverage: one workflow per named category, plus hello.
    const MANDATED: &[&str] = &[
        "hello-workflow",         // minimal hello-workflow
        "code-review-loop",       // code-review loop
        "parallel-tickets",       // parallel ticket implementation (fanout + merge)
        "repo-migration-sweep",   // repo migration sweep
        "gate-fix-loop",          // gate-fix loop (project-agnostic)
        "software-factory-slice", // software-factory slice
        "human-gate-approval",    // human-gate approval (approval_required stage)
        "durable-wait-signal",    // durable-wait / signal
        "fanout-merge",           // fanout + merge composition
        "cost-walkaway",          // cost-bounded walk-away
        "hermetic-build",         // sandboxed (oci) hermetic build
    ];

    let names = manifest_names();
    let missing: Vec<&str> = MANDATED
        .iter()
        .copied()
        .filter(|m| !names.iter().any(|n| n == m))
        .collect();
    assert!(
        missing.is_empty(),
        "MANIFEST.toml is missing mandated examples: {missing:?}\n  present: {names:?}"
    );

    // A count floor as a coarse backstop against wholesale erosion; the mandated
    // set above is the real coverage guarantee.
    let count = example_star_files().len();
    assert!(
        count >= MANDATED.len(),
        "the example corpus must carry >= {} workflows (the mandated set); found {count}",
        MANDATED.len()
    );
}

/// FAIL-CLOSED regression: a deliberately-broken `.star` dropped into an
/// examples-shaped tree (a test tempdir, never committed) is CAUGHT by the same
/// `load_check` predicate the gate runs. If this ever passes the broken file,
/// the whole gate is a no-op — so this proves the mechanism rejects breakage.
#[test]
fn a_deliberately_broken_example_is_caught() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    // A stage whose prompt references an UNKNOWN producer stage — a hard
    // load-time validation error (dangling structured-output reference).
    let broken = r#"
bad = stage(
    id = "bad",
    agent = "codex",
    prompt = "consume {{ stages.ghost.parsed.value }}",
)
workflow("deliberately-broken", root = [bad])
"#;
    let path = tmp.path().join("deliberately-broken.star");
    std::fs::write(&path, broken).expect("write broken example");

    let result = load_check(&path);
    assert!(
        result.is_err(),
        "a broken example must be REJECTED by the gate predicate, but load_check passed it"
    );

    // Control: a well-formed workflow written the same way DOES pass, so the
    // rejection above is about the defect, not the tempdir mechanics.
    let good = r#"
ok = stage(
    id = "ok",
    run = "printf '{\"ok\":true}\\n'",
    agent = "shell",
    outputs = {"ok": "bool"},
)
workflow("control-ok", root = [ok])
"#;
    let good_path = tmp.path().join("control-ok.star");
    std::fs::write(&good_path, good).expect("write control example");
    assert!(
        load_check(&good_path).is_ok(),
        "a well-formed control workflow must pass the gate predicate"
    );
}

/// `MANIFEST.toml` (consumed by `kata init` seeding) must list EXACTLY the
/// example `.star` files on disk — no orphan manifest rows, no unlisted files.
/// Keeps the seed manifest from drifting out of sync with the corpus.
#[test]
fn manifest_lists_every_example_and_vice_versa() {
    let manifest_path = examples_root().join("MANIFEST.toml");
    let manifest = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", manifest_path.display()));

    // Extract every `file = "..."` value (the manifest is simple, authored TOML).
    let mut listed: Vec<String> = manifest
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix("file")?.trim_start();
            let rest = rest.strip_prefix('=')?.trim();
            let inner = rest.strip_prefix('"')?;
            let end = inner.find('"')?;
            Some(inner[..end].to_string())
        })
        .collect();
    listed.sort();
    listed.dedup();

    let mut on_disk: Vec<String> = example_star_files()
        .iter()
        .map(|p| {
            p.strip_prefix(examples_root())
                .unwrap_or(p)
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    on_disk.sort();

    assert_eq!(
        listed, on_disk,
        "MANIFEST.toml `file =` entries must exactly match the example .star files \
         on disk.\n  manifest: {listed:?}\n  on disk:  {on_disk:?}"
    );
}

/// The user-visible symptom itself: every curated example resolves BY
/// NAME through the default roots.
///
/// A library that did not search the examples directory would fail
/// `kata check hello-workflow` with `workflow "hello-workflow" not found in any
/// library root` while the file sat in the shipped artifact. `default_roots()`
/// here exercises the
/// dev-checkout arm from a test exe under `<repo>/target`, which is the same
/// resolution an operator gets from a source checkout.
#[test]
fn every_manifest_example_resolves_by_name_through_default_roots() {
    let library = kata_program::library::WorkflowLibrary::default_roots();
    let names = manifest_names();
    assert!(!names.is_empty(), "manifest must declare example names");

    let mut failures = Vec::new();
    for name in &names {
        match library.resolve(name) {
            Ok(path) => {
                if !path.starts_with(examples_root()) {
                    failures.push(format!(
                        "{name}: resolved OUTSIDE the example pack, to {}",
                        path.display()
                    ));
                }
            }
            Err(err) => failures.push(format!("{name}: {err}")),
        }
    }
    assert!(
        failures.is_empty(),
        "every curated example must resolve by name through the default roots \
         (roots: {:?}):\n  {}",
        library.roots(),
        failures.join("\n  ")
    );
}

/// Because the example pack is a resolution root, a stem it shares
/// with a higher-priority bundled pack would SILENTLY change which file
/// `kata run <stem>` executes. The example root is last, so the stdlib wins —
/// which is the safe direction, but it also means the example silently becomes
/// unreachable by name. Keep the two sets disjoint so neither can happen.
#[test]
fn no_example_name_collides_with_a_bundled_stdlib_pack() {
    fn stems(dir: &Path) -> Vec<String> {
        let mut out = Vec::new();
        let mut files = Vec::new();
        if dir.is_dir() {
            collect_star(dir, &mut files);
        }
        for path in files {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                out.push(stem.to_string());
            }
        }
        out.sort();
        out
    }

    let wf = repo_root().join("workflows");
    let example_stems = stems(&examples_root());
    assert!(!example_stems.is_empty(), "example pack must not be empty");

    let mut collisions = Vec::new();
    for bundled in ["std", "kata-factory"] {
        let root = wf.join(bundled);
        for stem in stems(&root) {
            if example_stems.contains(&stem) {
                collisions.push(format!("{stem} (also in workflows/{bundled})"));
            }
        }
    }
    assert!(
        collisions.is_empty(),
        "an example stem collides with a higher-priority bundled pack, so the \
         example is unreachable by name and `kata run <stem>` silently runs the \
         other file:\n  {}",
        collisions.join("\n  ")
    );
}

/// `gate-fix-loop`'s `gate_run` reports by `printf`, so the gate output it
/// carries in `tail` must be a valid JSON string body whatever the gate
/// printed. The stage's checked `run=` is executed by `sh` with a gate that
/// prints a backslash, a quote, a C0 control byte, DEL, a multi-byte
/// character, a tab, a carriage return and a newline, and its stdout is read
/// by `serde_json` — a parser kata does not own — as one JSON object.
#[test]
fn gate_fix_loops_report_is_json_whatever_the_gate_printed() {
    let artifact = build_workflow_compiled_artifact_from_file(
        &examples_root().join("gate-fix-loop.star"),
        &loader_roots(),
    )
    .expect("gate-fix-loop compiles");
    let run = &artifact
        .execution_program
        .stages
        .iter()
        .find(|(id, _)| id.0 == "gate_run")
        .expect("gate-fix-loop has a gate_run stage")
        .1
        .op
        .prompt_template;
    let gate = r#"printf 'back\\slash "quote" ctl\001 del\177 caf\303\251 tab\there\r\nGATE-TAIL\n'; exit 3"#;
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(run)
        .env("GATE_COMMAND", gate)
        .output()
        .expect("sh runs the gate_run script");
    assert!(
        output.status.success(),
        "gate_run itself exits 0 and reports the gate's code: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "the report is not JSON ({err}): {:?}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_eq!(report["gate_status"], "red");
    assert_eq!(report["exit_code"], 3);
    let tail = report["tail"].as_str().expect("tail is a JSON string");
    assert!(
        tail.contains("slash") && tail.contains("quote") && tail.ends_with("GATE-TAIL"),
        "the tail keeps the gate's printable text: {tail:?}"
    );
}

/// **The five example packs that ran their model stages under `net = "host"`
/// only to reach the vendor now run them offline** (owner B5).
///
/// Each pack is checked on an installed node — every agent label it selects is
/// `nanocode_openai` over an `env:OPENAI_API_KEY` key, the shipped default kind,
/// and the node declares one `[node] egress_allow` authority. Every agent capsule the check
/// names must be `offline` — the model calls leave from the process hosting the
/// worker — and no row of any face may name the node's authority. A pack with
/// no agent row fails, so the cell cannot pass vacuously.
///
/// **Would red if:** one of these packs' model stages authored `net = "host"`
/// again (the row turns `egress` and carries [`NODE_AUTHORITY`]). Every model
/// stage here authors a sandbox profile, so the cell pins the packs' authoring
/// only; the unauthored default is pinned in `capsule_assembly.rs` and
/// `confined_default.rs`.
#[test]
fn the_example_packs_model_capsules_are_offline() {
    use kata_types::execution_contract::CapsuleNetworkPosture;

    const PACKS: [&str; 5] = [
        "code-review-loop.star",
        "gate-fix-loop.star",
        "gold-loop.star",
        "parallel-tickets.star",
        "software-factory-slice.star",
    ];
    const NODE_AUTHORITY: &str = "intranet.corp.example:443";

    kata_types::node_profile::mark_node_installed();
    let agents = ["default", "gate", "reviewer"]
        .map(|label| {
            (
                label.to_owned(),
                kata_types::config::AgentBackendConfig::Harness {
                    model: None,
                    reasoning_effort: None,
                    adapter: Some("nanocode_openai".to_owned()),
                    credential: Some(kata_types::config::AgentCredentialDecl {
                        mode: "api_key".to_owned(),
                        source: "env:OPENAI_API_KEY".to_owned(),
                    }),
                    env: std::collections::BTreeMap::new(),
                },
            )
        })
        .into_iter()
        .collect();
    kata_types::node_profile::install_node_agents(agents);
    kata_types::node_profile::install_node_egress_allow(std::collections::BTreeSet::from([
        kata_types::execution_contract::EgressAuthority::from_authority_str(NODE_AUTHORITY)
            .expect("an authority parses"),
    ]));

    for pack in PACKS {
        let path = examples_root().join(pack);
        let artifact = build_workflow_compiled_artifact_from_file(&path, &loader_roots())
            .unwrap_or_else(|e| panic!("{pack} checks on the installed node: {e}"));
        let mut agent_rows = 0;
        for stage in &artifact.preflight.stages {
            for row in &stage.capsule_networks {
                let rendered = format!("{:?}", row.network);
                assert!(
                    !rendered.contains(NODE_AUTHORITY),
                    "{pack}: stage {} reaches the node's authority: {rendered}",
                    stage.stage
                );
                if row.agent.is_some() {
                    agent_rows += 1;
                    assert_eq!(
                        row.network,
                        CapsuleNetworkPosture::Offline,
                        "{pack}: stage {} (agent {:?})",
                        stage.stage,
                        row.agent
                    );
                }
            }
        }
        assert!(agent_rows > 0, "{pack}: the check named no agent capsule");
    }
}
