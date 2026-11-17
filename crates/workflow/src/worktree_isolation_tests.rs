//! Tests for crates/workflow/src/worktree_isolation.rs. Extracted from the inline #[cfg(test)] module.

use super::*;

/// The candidate binding — minted from the RECORDED status, never a
/// disk scan — carries the recorded head, the recorded tree id (the promote
/// pin's currency), a clean `dirty`, and a deterministic fingerprint.
#[test]
fn validation_candidate_binding_recorded_mints_from_the_recorded_status() {
    use kata_effects_contract::RecordedWorkspaceStatus;
    let execution_id = Ulid::new();
    let recorded = RecordedWorkspaceStatus {
        workspace_root: std::path::PathBuf::from("/never/consulted"),
        head: "f".repeat(64),
        tree_id: "a".repeat(64),
    };
    let binding = crate::worktree_isolation::validation_candidate_binding_for_recorded(
        execution_id,
        Some("jj"),
        &recorded,
    )
    .expect("the recorded binding mints");
    assert_eq!(binding.execution_id, execution_id.to_string());
    assert_eq!(binding.head_commit.as_deref(), Some(recorded.head.as_str()));
    assert_eq!(
        binding.tree_id.as_deref(),
        Some(recorded.tree_id.as_str()),
        "the promote pin reads the recorded tree"
    );
    assert_eq!(binding.dirty, Some(false));
    assert!(binding.changed_paths.is_empty());
    // Deterministic: the same recorded status mints the same fingerprint.
    let again = crate::worktree_isolation::validation_candidate_binding_for_recorded(
        execution_id,
        Some("jj"),
        &recorded,
    )
    .unwrap();
    assert_eq!(binding.fingerprint, again.fingerprint);
    assert_eq!(binding.content_hash, again.content_hash);
    // And a different recorded candidate binds differently.
    let moved = RecordedWorkspaceStatus {
        workspace_root: std::path::PathBuf::from("/never/consulted"),
        head: recorded.head.clone(),
        tree_id: "b".repeat(64),
    };
    let other = crate::worktree_isolation::validation_candidate_binding_for_recorded(
        execution_id,
        Some("jj"),
        &moved,
    )
    .unwrap();
    assert_ne!(binding.fingerprint, other.fingerprint);
    assert_ne!(binding.content_hash, other.content_hash);
}

/// The fingerprint RECIPE, pinned to bytes: recorded validation-candidate
/// evidence stays comparable across builds only while this recipe is
/// byte-stable, and the `workspace_backend` label (`"jj"`) is one of its folds.
///
/// The expected hex was NOT produced by this crate: the preimage was spelled
/// field by field (each name, its length-prefixed value or presence byte, in
/// `validation_candidate_fingerprint`'s order) and hashed with the external
/// `b3sum` 1.8.7 CLI. A determinism or inequality check cannot see a dropped
/// or reordered fold; this can.
///
/// **Would RED if:** any field left, joined or moved in
/// `validation_candidate_content_hash` / `validation_candidate_fingerprint` —
/// the `workspace_backend` fold included — or a domain tag changed.
#[test]
fn validation_candidate_fingerprint_recipe_is_pinned_to_its_golden_bytes() {
    use kata_effects_contract::RecordedWorkspaceStatus;
    let execution_id: Ulid = "01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().expect("fixed ulid");
    let recorded = RecordedWorkspaceStatus {
        workspace_root: std::path::PathBuf::from("/never/consulted"),
        head: "f".repeat(64),
        tree_id: "a".repeat(64),
    };
    let jj = crate::worktree_isolation::validation_candidate_binding_for_recorded(
        execution_id,
        Some("jj"),
        &recorded,
    )
    .expect("the recorded binding mints");
    assert_eq!(
        jj.content_hash.to_string(),
        "939a500be7fcae7bbe0645b3ace212452d32516ea328d55b015b84ae68106bb5",
        "the candidate content-hash recipe moved: recorded evidence would rotate"
    );
    assert_eq!(
        jj.fingerprint.to_string(),
        "fb5336bcf7e63b6f916562d3dc034425d68a69baa021c26b6644372196219c6f",
        "the candidate fingerprint recipe moved: recorded evidence would rotate"
    );
    let unlabelled = crate::worktree_isolation::validation_candidate_binding_for_recorded(
        execution_id,
        None,
        &recorded,
    )
    .expect("the recorded binding mints");
    assert_eq!(
        unlabelled.fingerprint.to_string(),
        "9feb9b3e30191369d60711e86fc4330c985936f0f0b9d6e0b9d38454ea3421ae",
        "an absent backend label folds its own presence byte"
    );
}
