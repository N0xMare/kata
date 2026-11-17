//! Pin: ONE canonical project-local workflow root, and the root order
//! `kata run <name>` resolution and `kata workflows list` both consume.
//!
//! The workflow loader searches exactly one project-local root —
//! `<cwd>/.kata/workflows` — at highest priority, then the user root
//! `~/.kata/workflows`, then the bundled stdlib; there is no second
//! project-local library root to reconcile. This test pins that order so
//! `run` name-resolution and `workflows list` cannot silently disagree.

use std::path::PathBuf;

use kata_program::library::{WorkflowLibrary, resolve_default_roots};

fn write_flow(dir: &std::path::Path, name: &str) {
    std::fs::create_dir_all(dir).expect("create root");
    std::fs::write(dir.join(format!("{name}.star")), b"# stub\n").expect("write flow");
}

#[test]
fn canonical_project_root_is_first_then_user_then_bundled() {
    let project = std::env::temp_dir().join(format!("kata-roots-proj-{}", std::process::id()));
    let user = std::env::temp_dir().join(format!("kata-roots-user-{}", std::process::id()));

    // Pin the bundled tier deterministically via KATA_STDLIB_DIR-equivalent
    // injection so the order assertion does not depend on the host layout.
    let roots = resolve_default_roots(
        Some(&project),
        user.to_str(),
        Some("/opt/kata/share/kata/workflows"),
        None,
        "/x/crates/program",
    );

    // [0] project is the ONE canonical project-local root.
    assert_eq!(
        roots[0],
        project.join(".kata").join("workflows"),
        "the canonical project-local root is <cwd>/.kata/workflows"
    );
    // [1] user root.
    assert_eq!(roots[1], user.join(".kata").join("workflows"));
    // [2..] bundled tier (std + kata-factory sibling).
    assert_eq!(roots[2], PathBuf::from("/opt/kata/share/kata/workflows"));
    // Exactly one `.kata/workflows` per project — no competing project root.
    let project_roots = roots
        .iter()
        .filter(|r| r.ends_with("workflows") && r.starts_with(&project))
        .count();
    assert_eq!(project_roots, 1, "one project-local library root, not two");
}

#[test]
fn name_resolution_and_listing_agree_on_the_canonical_root() {
    let base = std::env::temp_dir().join(format!(
        "kata-roots-agree-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let project = base.join("project").join(".kata").join("workflows");
    let user = base.join("user").join(".kata").join("workflows");
    // The same name in BOTH roots: the project root must win (shadow the user).
    write_flow(&project, "shared");
    write_flow(&user, "shared");
    // A project-only name resolves from the project root.
    write_flow(&project, "proj-only");

    let library = WorkflowLibrary::new(vec![project.clone(), user.clone()]);

    // `kata run <name>` resolution: the project root wins.
    assert_eq!(
        library.resolve("shared").unwrap(),
        project.join("shared.star"),
        "a shared name resolves from the canonical project root"
    );
    assert_eq!(
        library.resolve("proj-only").unwrap(),
        project.join("proj-only.star")
    );

    // `kata workflows list` (effective) reports the SAME project-root winner
    // (root_priority 0), so listing and resolution cannot disagree.
    let effective = library.list_effective();
    let shared = effective
        .iter()
        .find(|e| e.name == "shared")
        .expect("shared listed");
    assert_eq!(shared.root_priority, 0, "listing picks the project root");
    assert_eq!(shared.path, project.join("shared.star"));

    let _ = std::fs::remove_dir_all(&base);
}
