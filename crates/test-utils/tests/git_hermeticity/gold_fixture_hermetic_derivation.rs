//! The shell materializer must agree with the compiled Rust override definition.

use kata_test_utils::git::HERMETIC_OVERRIDES;
use std::path::Path;
use std::process::Command;

#[test]
fn gold_fixture_parser_matches_the_compiled_override_set() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let result = Command::new("bash")
        .arg(root.join("scripts/materialize-gold-fixture.sh"))
        .arg(&repo)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    for (key, value) in HERMETIC_OVERRIDES {
        let actual = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["config", "--local", "--get", key])
            .output()
            .unwrap();
        assert!(actual.status.success(), "materializer omitted {key}");
        assert_eq!(
            String::from_utf8(actual.stdout).unwrap().trim(),
            *value,
            "{key}"
        );
    }
}
