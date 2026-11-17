//! `youki_registry` — the pinned runtime's own container registry, read from the HOST.
//!
//! Live cells assert that a teardown left nothing registered by reading `youki --root
//! <state> list` rather than asking kata. That read is only evidence when the listing
//! SUCCEEDED: youki 0.7.0's `list` loads every container's `state.json` before it
//! prints its table, so a single unreadable document (torn, corrupt, or unparseable)
//! fails the whole command with NOTHING on stdout — and an absence read off that empty
//! stdout passes whatever the runtime holds.

use std::path::Path;

use kata_types::youki_pin::YoukiPin;

/// `youki --root <state> list` with the pinned runtime, as its stdout table.
///
/// # Panics
///
/// When the pinned runtime cannot be spawned, or when `list` exits non-zero — a
/// listing that failed names no container either way, so it is refused here rather
/// than handed back as an empty table. Refused: a non-zero exit, for any cause. Not
/// refused: a state root that does not exist — `youki --root <dir>` creates it and
/// answers an empty table, so a caller whose absence claim depends on the path being
/// the right one must assert the root exists itself.
#[must_use]
pub fn youki_list(state: &Path) -> String {
    let output = std::process::Command::new(YoukiPin::embedded().store_path())
        .arg("--root")
        .arg(state)
        .arg("list")
        .output()
        .expect("the pinned runtime lists containers");
    assert!(
        output.status.success(),
        "`youki --root {} list` failed ({}), so it is no evidence about what the runtime \
         holds:\n{}",
        state.display(),
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}
