//! A capsule result's recorded output is a STAGE ENVELOPE: its `content` is the stage's
//! stdout, which the runner's structured-output validation reads. Without the key, every
//! capsule result with declared outputs would fail schema validation
//! (`envelope is missing a string "content" field`).

use kata_core::operational::{AdoptedResult, capsule_result_output};
use kata_types::execution_contract::{ArtifactPrivacy, ArtifactRef};
use kata_types::primitives::FixedBytes;
use kata_types::tree_artifact::TreeManifest;

#[test]
fn the_capsule_result_output_carries_stdout_as_the_envelope_content() {
    let stdout = "{\"dns_failed\": true, \"resolve_rc\": 127}\n";
    // The envelope's `content` is the ADOPTED capture's own verified bytes —
    // the refs name the artifacts; the text is read off them at adoption.
    let output = capsule_result_output(
        &AdoptedResult {
            artifact_id: [1; 32],
            manifest: TreeManifest::new(Vec::new()).unwrap(),
            member_bytes: 0,
            stdout: stdout.as_bytes().to_vec(),
            work_delta: None,
            agent: None,
        },
        &ArtifactRef::new(FixedBytes([2; 32]), 33, ArtifactPrivacy::Public),
        Some(0),
        &ArtifactRef::new(FixedBytes([3; 32]), 33, ArtifactPrivacy::Private),
        &ArtifactRef::new(FixedBytes([4; 32]), 0, ArtifactPrivacy::Private),
        false,
        None,
    );
    assert_eq!(output["content"], serde_json::json!(stdout));
    // `content` is the one copy: a second `stdout` key carried the same bytes twice and
    // had no reader.
    assert!(output.get("stdout").is_none(), "{output}");
}
