//! Tests for crates/program/src/library.rs. Extracted from the inline #[cfg(test)] module.

use std::path::{Path, PathBuf};

use kata_program::library::{
    WorkflowLibrary, incomplete_installed_layout_warning, no_roots_present_warning,
    resolve_default_roots,
};
use tempfile::TempDir;

fn touch(dir: &Path, relative: &str, content: &str) -> PathBuf {
    let path = dir.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&path, content).unwrap();
    path
}

// ---- WorkflowLibrary ----

#[test]
fn resolve_returns_first_matching_root() {
    let high = TempDir::new().unwrap();
    let low = TempDir::new().unwrap();
    touch(high.path(), "review.star", "# high");
    touch(low.path(), "review.star", "# low");

    let lib = WorkflowLibrary::new(vec![high.path().into(), low.path().into()]);
    let resolved = lib.resolve("review").unwrap();
    assert_eq!(resolved, high.path().join("review.star"));
}

#[test]
fn resolve_falls_through_to_lower_priority_root() {
    let high = TempDir::new().unwrap();
    let low = TempDir::new().unwrap();
    touch(low.path(), "review.star", "# low");

    let lib = WorkflowLibrary::new(vec![high.path().into(), low.path().into()]);
    let resolved = lib.resolve("review").unwrap();
    assert_eq!(resolved, low.path().join("review.star"));
}

#[test]
fn resolve_finds_star_workflow() {
    let root = TempDir::new().unwrap();
    touch(root.path(), "review.star", "# star");
    let lib = WorkflowLibrary::new(vec![root.path().into()]);
    assert_eq!(
        lib.resolve("review").unwrap(),
        root.path().join("review.star")
    );
}

/// A `.toml` file is not a recognized workflow definition: the resolver
/// only looks for `.star`, so a lone `review.toml` does not resolve.
#[test]
fn resolve_ignores_toml_files() {
    let root = TempDir::new().unwrap();
    touch(
        root.path(),
        "review.toml",
        "# toml is not a workflow frontend",
    );
    let lib = WorkflowLibrary::new(vec![root.path().into()]);
    assert!(lib.resolve("review").is_err());
}

#[test]
fn resolve_missing_name_returns_error() {
    let root = TempDir::new().unwrap();
    let lib = WorkflowLibrary::new(vec![root.path().into()]);
    let err = lib.resolve("nope").unwrap_err().to_string();
    assert!(err.contains("not found"), "{err}");
}

#[test]
fn resolve_rejects_traversal_and_slashes() {
    let lib = WorkflowLibrary::new(vec![PathBuf::from("/tmp")]);
    assert!(lib.resolve("../etc/passwd").is_err());
    assert!(lib.resolve("foo/bar").is_err());
    assert!(lib.resolve("").is_err());
}

#[test]
fn list_enumerates_all_entries_and_marks_shadowing() {
    let high = TempDir::new().unwrap();
    let low = TempDir::new().unwrap();
    touch(high.path(), "review.star", "# high");
    touch(low.path(), "review.star", "# low");
    touch(low.path(), "only-in-low.star", "# only-in-low");

    let lib = WorkflowLibrary::new(vec![high.path().into(), low.path().into()]);
    let all = lib.list();
    assert_eq!(all.len(), 3);

    let effective = lib.list_effective();
    let names: Vec<&str> = effective.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"review"));
    assert!(names.contains(&"only-in-low"));
    // `review` resolves to the high-priority root.
    let review = effective.iter().find(|e| e.name == "review").unwrap();
    assert_eq!(review.root_priority, 0);
    assert_eq!(review.path, high.path().join("review.star"));
}

/// A library lists a `.star` file and never a `.toml` one: `.toml` is not a
/// workflow frontend. The listing row's `format` wire value (`"starlark"`) is
/// pinned on the REST rows `GET /workflows` and `GET /workflows/{name}` serve
/// (`list_workflows_populated_exposes_entry_fields` and
/// `get_workflow_found_returns_stage_summary` in `crates/api`).
#[test]
fn list_admits_star_files_and_not_toml_files() {
    let root = TempDir::new().unwrap();
    touch(root.path(), "demo.star", "# demo");
    touch(root.path(), "review.toml", "# review");

    let lib = WorkflowLibrary::new(vec![root.path().into()]);
    let entries = lib.list_effective();

    assert!(entries.iter().any(|e| e.name == "demo"));
    assert!(
        entries.iter().all(|e| e.name != "review"),
        "a .toml file must not be listed as a workflow entry"
    );
}

// ---- read_pack_metadata ----

/// A pack that declares `description=`/`version=`/`tags=`/`params=` surfaces
/// all four through `WorkflowLibrary::read_pack_metadata` — the exact surface
/// `kata workflows list` reads to render the richer metadata line.
#[test]
fn read_pack_metadata_surfaces_description_version_tags_params() {
    let root = TempDir::new().unwrap();
    touch(
        root.path(),
        "annotated.star",
        r#"
s = stage(prompt = "do it", agent = "worker")
workflow(
    "annotated",
    root = s,
    description = "does the thing",
    version = "1.2.3",
    tags = ["alpha", "beta"],
    params = {"target_repo": "string"},
)
"#,
    );

    let lib = WorkflowLibrary::new(vec![root.path().into()]);
    let entry = lib
        .list_effective()
        .into_iter()
        .find(|e| e.name == "annotated")
        .expect("annotated entry must be listed");

    let metadata = lib
        .read_pack_metadata(&entry)
        .expect("annotated pack must compile and yield metadata");
    assert_eq!(metadata.description.as_deref(), Some("does the thing"));
    assert_eq!(metadata.version.as_deref(), Some("1.2.3"));
    assert_eq!(metadata.tags, vec!["alpha".to_owned(), "beta".to_owned()]);
    assert_eq!(
        metadata.params,
        vec![("target_repo".to_owned(), "string".to_owned())]
    );
}

/// A pack that omits `version=`/`tags=`/`params=` loads through
/// `read_pack_metadata`, with those fields defaulting to `None`/empty.
#[test]
fn read_pack_metadata_defaults_when_omitted() {
    let root = TempDir::new().unwrap();
    touch(
        root.path(),
        "bare.star",
        r#"
s = stage(prompt = "do it", agent = "worker")
workflow("bare", root = s)
"#,
    );

    let lib = WorkflowLibrary::new(vec![root.path().into()]);
    let entry = lib
        .list_effective()
        .into_iter()
        .find(|e| e.name == "bare")
        .expect("bare entry must be listed");

    let metadata = lib
        .read_pack_metadata(&entry)
        .expect("a pack omitting the metadata fields must load");
    assert_eq!(metadata.description, None);
    assert_eq!(metadata.version, None);
    assert!(metadata.tags.is_empty());
    assert!(metadata.params.is_empty());
}

// ---- default-root resolution + loud degrade ----

/// `default_roots` must resolve the
/// INSTALLED layout — `<exe>/../share/kata/{workflows,kata-factory}` —
/// so a binary copied to a fresh box next to its `share/` tree finds the
/// stdlib. We simulate the dist layout in a tempdir with a fake exe path
/// and assert both installed roots materialize, in order. This is the
/// machine-checkable half of the `just package` fresh-box boot checkpoint.
#[test]
fn resolve_default_roots_finds_installed_layout_relative_to_exe() {
    let dist = TempDir::new().unwrap();
    // dist/bin/kata (fake exe) + dist/share/kata/{workflows,kata-factory}
    let exe = dist.path().join("bin").join("kata");
    std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
    std::fs::write(&exe, b"#!/bin/true\n").unwrap();
    let share = dist.path().join("share").join("kata");
    let installed_workflows = share.join("workflows");
    let installed_factory = share.join("kata-factory");
    std::fs::create_dir_all(&installed_workflows).unwrap();
    std::fs::create_dir_all(&installed_factory).unwrap();

    // KATA_STDLIB_DIR unset (None) so the installed-layout branch runs.
    let roots = resolve_default_roots(
        None,
        None,
        None,
        Some(exe.as_path()),
        env!("CARGO_MANIFEST_DIR"),
    );

    assert!(
        roots.contains(&installed_workflows),
        "installed workflows root must resolve relative to the exe; got {roots:?}"
    );
    assert!(
        roots.contains(&installed_factory),
        "installed kata-factory root must resolve relative to the exe; got {roots:?}"
    );
    // Installed workflows must precede its kata-factory sibling.
    let wf_idx = roots
        .iter()
        .position(|r| r == &installed_workflows)
        .unwrap();
    let fac_idx = roots.iter().position(|r| r == &installed_factory).unwrap();
    assert!(
        wf_idx < fac_idx,
        "workflows must precede kata-factory: {roots:?}"
    );
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf();
    assert!(
        !roots.iter().any(|root| root.starts_with(&repo)),
        "installed layout must not leak compile-time checkout roots: {roots:?}"
    );
}

#[test]
fn resolve_default_roots_uses_checkout_only_when_installed_layout_is_absent() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf();
    let exe = repo.join("target").join("debug").join("kata");

    let roots = resolve_default_roots(
        None,
        None,
        None,
        Some(exe.as_path()),
        env!("CARGO_MANIFEST_DIR"),
    );

    assert!(roots.contains(&repo.join("workflows").join("std")));
    assert!(roots.contains(&repo.join("workflows").join("kata-factory")));
}

#[test]
fn copied_binary_with_missing_bundle_never_reaches_back_into_checkout() {
    let dist = TempDir::new().unwrap();
    let exe = dist.path().join("bin").join("kata");
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf();

    let roots = resolve_default_roots(
        None,
        None,
        None,
        Some(exe.as_path()),
        env!("CARGO_MANIFEST_DIR"),
    );

    assert!(
        !roots.iter().any(|root| root.starts_with(&repo)),
        "{roots:?}"
    );
}

#[test]
fn partial_installed_bundle_is_loud_and_never_completed_from_checkout() {
    let dist = TempDir::new().unwrap();
    let exe = dist.path().join("bin").join("kata");
    let workflows = dist.path().join("share").join("kata").join("workflows");
    std::fs::create_dir_all(&workflows).unwrap();
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf();

    let roots = resolve_default_roots(
        None,
        None,
        None,
        Some(exe.as_path()),
        env!("CARGO_MANIFEST_DIR"),
    );
    assert!(roots.contains(&workflows));
    assert!(
        !roots.iter().any(|root| root.starts_with(&repo)),
        "{roots:?}"
    );
    let warning = incomplete_installed_layout_warning(Some(&exe), None)
        .expect("partial installed pair must be diagnosed");
    assert!(warning.contains("INCOMPLETE installed bundle"), "{warning}");
    assert!(warning.contains("will not read"), "{warning}");
}

/// An explicit `KATA_STDLIB_DIR` wins and pulls in its
/// `kata-factory` sibling — the installed-exe branch is not consulted.
#[test]
fn resolve_default_roots_honors_explicit_stdlib_dir_with_factory_sibling() {
    let base = TempDir::new().unwrap();
    let stdlib = base.path().join("workflows");
    let factory = base.path().join("kata-factory");
    let roots = resolve_default_roots(
        None,
        None,
        stdlib.to_str(),
        None,
        env!("CARGO_MANIFEST_DIR"),
    );
    assert!(
        roots.contains(&stdlib),
        "explicit stdlib dir must be a root: {roots:?}"
    );
    assert!(
        roots.contains(&factory),
        "kata-factory sibling of the explicit stdlib dir must be a root: {roots:?}"
    );
}

/// An EMPTY `KATA_STDLIB_DIR` (`export KATA_STDLIB_DIR=`) must be
/// treated as unset — the installed-layout branch still runs — rather than
/// injecting a bogus empty `""` root that shadows the real install.
#[test]
fn resolve_default_roots_empty_stdlib_dir_falls_through_to_installed_layout() {
    let dist = TempDir::new().unwrap();
    let exe = dist.path().join("bin").join("kata");
    std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
    std::fs::write(&exe, b"#!/bin/true\n").unwrap();
    let installed_workflows = dist.path().join("share").join("kata").join("workflows");

    let roots = resolve_default_roots(
        None,
        None,
        Some(""), // empty override — must be ignored
        Some(exe.as_path()),
        env!("CARGO_MANIFEST_DIR"),
    );
    assert!(
        roots.contains(&installed_workflows),
        "empty KATA_STDLIB_DIR must fall through to installed layout; got {roots:?}"
    );
    assert!(
        !roots.iter().any(|r| r.as_os_str().is_empty()),
        "empty KATA_STDLIB_DIR must not inject a bogus empty root; got {roots:?}"
    );
}

/// When ALL roots are absent, the library degrades LOUDLY — the
/// warning names every tried path and points the operator at the fix.
#[test]
fn no_roots_present_warning_is_loud_when_all_absent() {
    let missing = TempDir::new().unwrap();
    let a = missing.path().join("nope-a");
    let b = missing.path().join("nope-b");
    let warning = no_roots_present_warning(&[a.clone(), b.clone()])
        .expect("all-absent roots must produce a loud degrade warning");
    // Names the tried paths and the operator remedy.
    assert!(
        warning.contains("nope-a"),
        "warning must name tried path a: {warning}"
    );
    assert!(
        warning.contains("nope-b"),
        "warning must name tried path b: {warning}"
    );
    assert!(
        warning.contains("KATA_STDLIB_DIR") || warning.contains("just package"),
        "warning must point at the fix: {warning}"
    );
}

/// The moment one root exists, the degrade warning is silent — a
/// healthy library must not spam operators.
#[test]
fn no_roots_present_warning_silent_when_one_root_exists() {
    let present = TempDir::new().unwrap();
    let real = present.path().join("real");
    std::fs::create_dir_all(&real).unwrap();
    let ghost = present.path().join("ghost");
    assert!(
        no_roots_present_warning(&[ghost, real]).is_none(),
        "a library with at least one existing root must not warn"
    );
}

// ---- the curated example pack is a bundled resolution root ----

/// The curated example pack is a BUNDLED RESOLUTION ROOT in every
/// bundled mode, and it is always the last BUNDLED root.
///
/// Without it `kata run hello-workflow` would fail with `not found in any
/// library root` while the artifact shipped the file.
///
/// The index assertion is the load-bearing half: examples must come after
/// kata-factory (and therefore after project, user and std), so the learning
/// surface is resolvable by name yet can never shadow a workflow that already
/// resolves. Only the explicit mode's `smoke` sibling — the gate rigs, which no
/// bundle carries — follows it.
#[test]
fn resolve_default_roots_carries_the_examples_root_in_every_bundled_mode() {
    fn assert_examples_last(roots: &[PathBuf], examples: &Path, factory: &Path, mode: &str) {
        let examples_idx = roots
            .iter()
            .position(|root| root == examples)
            .unwrap_or_else(|| {
                panic!("{mode}: examples must be a bundled root; got {roots:?}");
            });
        let factory_idx = roots
            .iter()
            .position(|root| root == factory)
            .unwrap_or_else(|| panic!("{mode}: kata-factory root missing; got {roots:?}"));
        assert!(
            factory_idx < examples_idx,
            "{mode}: examples must be the LAST bundled root so it can never shadow: {roots:?}"
        );
        assert_eq!(
            examples_idx,
            roots.len() - 1,
            "{mode}: examples must be the lowest-priority root overall: {roots:?}"
        );
    }

    // (1) Installed layout: <exe>/../share/kata/{workflows,kata-factory,examples}.
    let dist = TempDir::new().unwrap();
    let exe = dist.path().join("bin").join("kata");
    std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
    std::fs::write(&exe, b"#!/bin/true\n").unwrap();
    let share = dist.path().join("share").join("kata");
    for root in ["workflows", "kata-factory", "examples"] {
        std::fs::create_dir_all(share.join(root)).unwrap();
    }
    let installed = resolve_default_roots(
        None,
        None,
        None,
        Some(exe.as_path()),
        env!("CARGO_MANIFEST_DIR"),
    );
    assert_examples_last(
        &installed,
        &share.join("examples"),
        &share.join("kata-factory"),
        "installed",
    );

    // (2) Explicit KATA_STDLIB_DIR: its `examples` sibling joins the tier,
    // followed only by its `smoke` sibling.
    let base = TempDir::new().unwrap();
    let stdlib = base.path().join("workflows");
    let mut explicit = resolve_default_roots(
        None,
        None,
        stdlib.to_str(),
        None,
        env!("CARGO_MANIFEST_DIR"),
    );
    assert_eq!(
        explicit.pop(),
        Some(base.path().join("smoke")),
        "explicit KATA_STDLIB_DIR: its `smoke` sibling is the lowest-priority root"
    );
    assert_examples_last(
        &explicit,
        &base.path().join("examples"),
        &base.path().join("kata-factory"),
        "explicit KATA_STDLIB_DIR",
    );

    // (3) Dev checkout fallback: <repo>/workflows/{std,kata-factory,examples}.
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf();
    let dev_exe = repo.join("target").join("debug").join("kata");
    let dev = resolve_default_roots(
        None,
        None,
        None,
        Some(dev_exe.as_path()),
        env!("CARGO_MANIFEST_DIR"),
    );
    assert_examples_last(
        &dev,
        &repo.join("workflows").join("examples"),
        &repo.join("workflows").join("kata-factory"),
        "dev checkout",
    );
}

/// The gate's smoke rigs (`workflows/smoke`) resolve ONLY through an explicit
/// `KATA_STDLIB_DIR` naming the checkout's `workflows/std`: an installed layout —
/// even one with a stray `share/kata/smoke` beside it — and a checkout build
/// (the source install) neither list nor resolve them. Read against the
/// checkout's real `workflows/smoke` directory, so the rig a refusal names is a
/// file on disk, not a name this test invented.
///
/// **Would red if:** the installed or checkout-fallback branch named a `smoke`
/// root, or the explicit branch dropped its `smoke` sibling.
#[test]
fn smoke_rigs_resolve_only_through_an_explicit_stdlib_dir() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf();
    let smoke = repo.join("workflows").join("smoke");
    let rig = std::fs::read_dir(&smoke)
        .expect("workflows/smoke reads")
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            (path.extension().is_some_and(|ext| ext == "star"))
                .then(|| path.file_stem()?.to_str().map(str::to_owned))
                .flatten()
        })
        .min()
        .expect("workflows/smoke holds a rig");

    let dist = TempDir::new().unwrap();
    let exe = dist.path().join("bin").join("kata");
    std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
    std::fs::write(&exe, b"#!/bin/true\n").unwrap();
    let share = dist.path().join("share").join("kata");
    for root in ["workflows", "kata-factory", "examples", "smoke"] {
        std::fs::create_dir_all(share.join(root)).unwrap();
    }
    std::fs::write(
        share.join("smoke").join(format!("{rig}.star")),
        b"# stray\n",
    )
    .unwrap();
    let installed = WorkflowLibrary::new(resolve_default_roots(
        None,
        None,
        None,
        Some(exe.as_path()),
        env!("CARGO_MANIFEST_DIR"),
    ));
    let checkout = WorkflowLibrary::new(resolve_default_roots(
        None,
        None,
        None,
        Some(repo.join("target").join("debug").join("kata").as_path()),
        env!("CARGO_MANIFEST_DIR"),
    ));
    for (mode, library) in [("installed", &installed), ("checkout", &checkout)] {
        assert!(
            library.resolve(&rig).is_err(),
            "{mode}: the rig {rig} must not resolve; roots {:?}",
            library.roots()
        );
        assert!(
            !library.list().iter().any(|entry| entry.name == rig),
            "{mode}: the rig {rig} must not be listed; roots {:?}",
            library.roots()
        );
    }

    let stdlib = repo.join("workflows").join("std");
    let explicit = WorkflowLibrary::new(resolve_default_roots(
        None,
        None,
        stdlib.to_str(),
        None,
        env!("CARGO_MANIFEST_DIR"),
    ));
    assert_eq!(
        explicit.resolve(&rig).expect("the rig resolves explicitly"),
        smoke.join(format!("{rig}.star")),
    );
}

/// The installed bundle is a TRIPLE, so a tree carrying two of the
/// three directories is an incomplete install and must be named as one — it
/// resolves strictly fewer workflows by name than the artifact advertises.
#[test]
fn incomplete_installed_layout_warning_covers_a_missing_examples_root() {
    let dist = TempDir::new().unwrap();
    let exe = dist.path().join("bin").join("kata");
    std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
    std::fs::write(&exe, b"#!/bin/true\n").unwrap();
    let share = dist.path().join("share").join("kata");
    std::fs::create_dir_all(share.join("workflows")).unwrap();
    std::fs::create_dir_all(share.join("kata-factory")).unwrap();

    let warning = incomplete_installed_layout_warning(Some(&exe), None)
        .expect("two of three bundled roots is an INCOMPLETE install");
    assert!(warning.contains("INCOMPLETE installed bundle"), "{warning}");
    assert!(
        warning.contains(&share.join("examples").display().to_string()),
        "the warning must name the missing examples root: {warning}"
    );

    // Uniformly present is healthy and silent.
    std::fs::create_dir_all(share.join("examples")).unwrap();
    assert!(
        incomplete_installed_layout_warning(Some(&exe), None).is_none(),
        "a complete triple must not warn"
    );
}
