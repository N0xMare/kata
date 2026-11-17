//! `docs/product/operator-guide.md` ↔ product drift guard for the STAGE RESULT SHAPE.
//!
//! The quickstart is the first hour of a stranger's life with kata, and its
//! "Run output" transcript must show the CURRENT band layout. A transcript
//! that showed `exit_code`, `duration_ms`, `stderr` and `stdout` INSIDE
//! `parsed`, the author's own namespace, would teach a shape that fails the
//! stage with `missing declared field "exit_code"` once copied into an
//! `outputs=` block — a hard failure in a first authoring session, caused by
//! the doc rather than by the author.
//!
//! **They compare the doc against the product's own code, never against a
//! second copy of the shape typed into this file.** The expected key set is
//! derived by calling `kata_core::operational::capsule_result_output` — the one
//! writer of a capsule stage's recorded output, whose root `exit_code` the live
//! capsule cells read — so a future shape change fails here with the doc named
//! rather than silently re-rotting it.
//!
//! A workflow runs only on an installed main, so these cells pin the packs
//! COMPILING (`kata check`, a node-less door that boots nothing and needs no
//! model CLI); the emitted-envelope halves live on the live OCI cells that run
//! a booted node.

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("bin/kata lives two levels below the repo root")
        .to_path_buf()
}

fn quickstart() -> &'static str {
    static DOC: OnceLock<String> = OnceLock::new();
    DOC.get_or_init(|| {
        let path = repo_root().join("docs/product/operator-guide.md");
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
    })
}

fn kata() -> Command {
    Command::new(env!("CARGO_BIN_EXE_kata"))
}

/// Every key a shell stage's recorded output carries, taken from the WRITER
/// rather than retyped here: `capsule_result_output` builds the record a capsule
/// stage's `outputs[stage]` holds, and the runner adds only `parsed` beside it.
/// These names are the engine's and never an author's.
fn capsule_result_keys() -> Vec<String> {
    use kata_core::operational::{AdoptedResult, capsule_result_output};
    use kata_types::execution_contract::{ArtifactPrivacy, ArtifactRef};
    use kata_types::primitives::FixedBytes;
    use kata_types::tree_artifact::TreeManifest;

    let output = capsule_result_output(
        &AdoptedResult {
            artifact_id: [1; 32],
            manifest: TreeManifest::new(Vec::new()).expect("the empty manifest is valid"),
            member_bytes: 0,
            stdout: b"{}\n".to_vec(),
            work_delta: None,
            agent: None,
        },
        &ArtifactRef::new(FixedBytes([2; 32]), 0, ArtifactPrivacy::Public),
        Some(0),
        &ArtifactRef::new(FixedBytes([3; 32]), 3, ArtifactPrivacy::Private),
        &ArtifactRef::new(FixedBytes([4; 32]), 0, ArtifactPrivacy::Private),
        false,
        None,
    );
    output
        .as_object()
        .expect("a capsule_result record is a JSON object")
        .keys()
        .cloned()
        .collect()
}

/// The keys of `object` (which starts at its `{`), at its own top level only:
/// keys of nested objects and text inside strings are skipped.
fn top_level_keys(object: &str) -> Vec<String> {
    let bytes = object.as_bytes();
    assert_eq!(bytes.first(), Some(&b'{'), "top_level_keys takes an object");
    let mut keys = Vec::new();
    let mut depth = 0usize;
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'{' | b'[' => depth += 1,
            b'}' | b']' => depth -= 1,
            b'"' => {
                let start = cursor + 1;
                let mut end = start;
                while bytes[end] != b'"' {
                    end += if bytes[end] == b'\\' { 2 } else { 1 };
                }
                cursor = end;
                if depth == 1 && bytes.get(end + 1) == Some(&b':') {
                    keys.push(object[start..end].to_owned());
                }
            }
            _ => {}
        }
        cursor += 1;
    }
    keys
}

/// The balanced `{ .. }` substring starting at `open`, which must index the
/// opening brace. Quote-aware so a brace inside a JSON string cannot unbalance
/// it (`"stdout":"{\"greeting\"..."` is exactly that case).
fn balanced_object(text: &str, open: usize) -> &str {
    let bytes = text.as_bytes();
    assert_eq!(bytes[open], b'{', "balanced_object must start at a brace");
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, byte) in bytes[open..].iter().enumerate() {
        if in_string {
            match byte {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &text[open..=open + offset];
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced object starting at byte {open}");
}

/// Every `"parsed":{ .. }` object literal written anywhere in the quickstart.
fn parsed_literals(doc: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(hit) = doc[cursor..].find("\"parsed\":") {
        let colon = cursor + hit + "\"parsed\":".len();
        let brace = doc[colon..]
            .find('{')
            .map(|o| colon + o)
            .expect("a `\"parsed\":` sample must be followed by an object");
        // Only treat it as a literal when the brace is adjacent (allowing
        // whitespace) — prose like `"parsed" is your namespace` has none.
        if doc[colon..brace].trim().is_empty() {
            out.push(balanced_object(doc, brace));
        }
        cursor = colon;
    }
    out
}

/// The fenced block of `lang` that contains `needle`, without its fences.
fn fenced_block_containing(doc: &str, lang: &str, needle: &str) -> String {
    let fence = format!("```{lang}\n");
    let mut cursor = 0usize;
    while let Some(hit) = doc[cursor..].find(&fence) {
        let body_start = cursor + hit + fence.len();
        let body_end = body_start
            + doc[body_start..]
                .find("\n```")
                .expect("a fenced block must close");
        let body = &doc[body_start..body_end];
        if body.contains(needle) {
            return body.to_owned();
        }
        cursor = body_end;
    }
    panic!("no ```{lang} block in the quickstart contains {needle:?}");
}

// ─────────────────────────── the drift guards ───────────────────────────

/// RED on a transcript reading
/// `"parsed":{"exit_code":0,"greeting":"hello from kata","stdout":"…"}`: two of
/// the three keys it shows an author in their own namespace are engine facts
/// that namespace does not receive.
#[test]
fn no_quickstart_sample_puts_an_engine_fact_inside_parsed() {
    let doc = quickstart();
    let facts = capsule_result_keys();
    let literals = parsed_literals(doc);
    assert!(
        !literals.is_empty(),
        "the quickstart must keep showing a `parsed` band — a guard over zero \
         samples proves nothing"
    );
    for literal in &literals {
        for fact in &facts {
            let key = format!("\"{fact}\":");
            assert!(
                !literal.contains(&key),
                "the quickstart shows the engine-owned fact `{fact}` INSIDE a `parsed` \
                 band. `parsed` is the AUTHOR's namespace and carries only what \
                 `outputs=`/`produces=` declared; the engine's facts sit beside it at the \
                 root of the stage's `capsule_result` record \
                 (`kata_core::operational::capsule_result_output`). A reader who copies \
                 this into an `outputs=` block gets `missing declared field \"{fact}\"`.\n\
                 Sample:\n{literal}",
            );
        }
        assert!(
            !literal.contains("\"stdout\":"),
            "the quickstart shows `stdout` inside a `parsed` band. There is no `stdout` \
             key anywhere in a stage result: for a shell stage the payload band \
             (`content`) IS stdout, and duplicating it would double capped ledger \
             bytes.\nSample:\n{literal}"
        );
    }
}

/// The doc's "Run output" transcript must show the stage record the PRODUCT writes.
///
/// The record is read off a booted node by the live cells; this cell keeps the
/// host-free halves — the transcript's pack compiles through `kata check`, and the
/// transcript's stage entry shows only keys `capsule_result_output` writes (plus
/// the runner's `parsed`), including the root `exit_code` the guide tells a reader
/// to read.
#[test]
fn quickstart_stage_output_sample_shows_the_record_the_product_writes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pack = dir.path().join("hello.star");
    // The shape of `std.hello`, which is the workflow the transcript runs.
    std::fs::write(
        &pack,
        r#"
hello = stage(
    id = "hello",
    run = """
printf '{"greeting":"hello from kata"}\n'
""",
    agent = "shell",
    outputs = {"greeting": "string"},
)
workflow("quickstart-hello-shape", description = "the transcript's shape", root = [hello])
"#,
    )
    .expect("write pack");

    // The pack still compiles — the transcript's snippet is what a new author types.
    let checked = kata()
        .arg("check")
        .arg(&pack)
        .output()
        .expect("kata check spawns");
    assert!(
        checked.status.success(),
        "the run-output hello pack must compile under the shipped profile; stderr:\n{}",
        String::from_utf8_lossy(&checked.stderr)
    );

    // (2) The transcript's stage entry is the record the writer produces. Every
    // key it shows must be one `capsule_result_output` writes, or the runner's
    // `parsed`; and it must show the keys the guide's prose names.
    let sample = fenced_block_containing(quickstart(), "console", "kata run std.hello --wait");
    let entry_start = sample.find("\"hello\":{").map_or_else(
        || panic!("the transcript shows no `hello` stage entry:\n{sample}"),
        |at| at + "\"hello\":".len(),
    );
    let shown = top_level_keys(balanced_object(&sample, entry_start));
    let written = capsule_result_keys();
    for key in &shown {
        assert!(
            key == "parsed" || written.contains(key),
            "docs/product/operator-guide.md's run transcript shows `{key}` on the stage \
             entry, which a capsule stage's record does not carry. Its entry is the \
             `capsule_result` record (`kata_core::operational::capsule_result_output`) \
             plus the runner's `parsed`.\nWritten keys: {written:?}\nTranscript:\n{sample}",
        );
    }
    for key in ["parsed", "content", "exit_code", "kind"] {
        assert!(
            shown.iter().any(|shown| shown == key),
            "docs/product/operator-guide.md's run transcript does not show `{key}` on the \
             stage entry; the guide's prose names it, and the product writes it on every \
             capsule stage's record.\nTranscript:\n{sample}",
        );
    }
    let exit_code_doc = "`outputs.boom.exit_code`";
    assert!(
        quickstart().contains(exit_code_doc) && written.iter().any(|key| key == "exit_code"),
        "the guide must send a reader to the stage record's ROOT `exit_code` \
         ({exit_code_doc}), the position `capsule_result_output` writes",
    );
}

/// The "Authoring diagnostics" section prints the accepted-keyword menu and
/// calls it "the authoritative surface reference", so its copy must be exactly
/// what `kata check` prints: a stale copy hides keywords (such as
/// `exit_policy`, which the shell-exit section recommends) from the reader.
#[test]
fn quickstart_prints_the_real_accepted_stage_keyword_menu() {
    let dir = tempfile::tempdir().expect("tempdir");
    let broken = dir.path().join("broken.star");
    // The section's own two-defect file, verbatim.
    std::fs::write(
        &broken,
        "s = stage(id=\"greet\", run=\"echo hi\", agent=\"shell\", model=\"sonnet\")\n\
         workflow(\"broken\", stages=[s])\n",
    )
    .expect("write broken pack");

    let output = kata()
        .arg("check")
        .arg(&broken)
        .output()
        .expect("kata check spawns");
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let doc = quickstart();
    for menu in [
        "accepted stage() keywords:",
        "accepted workflow() keywords:",
    ] {
        let line = rendered
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with(menu))
            .unwrap_or_else(|| panic!("`kata check` prints {menu:?}; got:\n{rendered}"));
        assert!(
            doc.contains(line),
            "docs/product/operator-guide.md's \"Authoring diagnostics\" section reproduces the \
             DSL keyword menu and calls it the authoritative surface reference, but its copy \
             is not what the binary prints.\n\
             binary: {line}\n\
             Re-capture its `kata check ./broken.star` transcript."
        );
    }
}

/// The shell-exit section tells a reader how a non-zero shell exit maps to the
/// run's verdict: the direct mechanism, `exit_policy="zero_success"`, is the
/// DEFAULT, and listing only INDIRECT workarounds (`timeout_ms`, an agent
/// error, a validator/bound) would omit it.
///
/// This asserts BOTH of the doc's snippets, extracted rather than retyped,
/// because the section makes two claims that only mean something together: a
/// stage that authors nothing FAILS, and the same stage declaring the `content`
/// opt-out COMPLETES. A test that ran only the first would go on passing if
/// `exit_policy=` stopped being honoured at all.
///
/// The snippets are checked for COMPILATION host-free; the fail-vs-complete
/// semantics themselves run on the live OCI surface, which is where the doc's
/// `kata run ... --wait` transcript lives anyway.
#[test]
fn quickstart_names_the_direct_ci_failure_mechanism_and_the_snippets_compile() {
    let doc = quickstart();
    let ci_section = doc
        .split("### A non-zero shell exit FAILS the run — unless you say otherwise")
        .nth(1)
        .expect("the guide keeps its shell-exit-code section")
        .split("\n## ")
        .next()
        .expect("section body");
    assert!(
        ci_section.contains("zero_success"),
        "the shell-exit section must name `exit_policy=\"zero_success\"` — the DEFAULT \
         and the mechanism that turns a non-zero shell exit into a Failed run. A section that \
         only listed `timeout_ms` / agent-error / bound would send a reader to three \
         workarounds for the thing the product does by default.\nSection:\n{ci_section}"
    );
    assert!(
        ci_section.contains("exit_policy=\"content\"")
            || ci_section.contains("exit_policy = \"content\""),
        "the shell-exit section must also name the OPT-OUT. The default is only safe advice \
         if the reader is told the one spelling that lets a gate/loop pack that reads the \
         exit code complete on a non-zero exit.\nSection:\n{ci_section}"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let check_snippet = |name: &str, snippet: &str| {
        let pack = dir.path().join(name);
        std::fs::write(&pack, snippet).expect("write snippet");
        let checked = kata()
            .arg("check")
            .arg(&pack)
            .output()
            .expect("kata check spawns");
        assert!(
            checked.status.success(),
            "the shell-exit section's `{name}` snippet must compile; stderr:\n{}",
            String::from_utf8_lossy(&checked.stderr)
        );
    };

    // ---- ARM 1: the DEFAULT snippet — authors no `exit_policy=`, so its run FAILS.
    // Selected by the workflow NAME rather than by the kwarg, because the whole
    // point of this arm is that the snippet carries no kwarg to select on.
    //
    // The exit-code semantics the section documents are exercised on a booted node (the
    // live OCI smokes).
    let default_snippet = fenced_block_containing(doc, "python", "\"nonzero-exit\"");
    assert!(
        !default_snippet.contains("exit_policy"),
        "ARM 1's snippet must author NO exit_policy — it is the doc's claim about the \
         DEFAULT. Got:\n{default_snippet}"
    );
    check_snippet("nonzero-exit.star", &default_snippet);

    // ---- ARM 2: the OPT-OUT snippet — one kwarg, same body — compiles.
    let opt_out_snippet = fenced_block_containing(doc, "python", "exit_policy = \"content\"");
    check_snippet("content-exit-probe.star", &opt_out_snippet);
}
