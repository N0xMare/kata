//! HOST-INDEPENDENT: the provider protocol's admission fold, its frame codec,
//! the supervisor's floor invariant, and the providers' dependency closure
//! (a provider is NOT LINKED INTO KATA).
//!
//! # Nothing here needs a kernel, and that is the point of the split
//!
//! The one claim that requires a kernel — *the floor survives the handoff* — is
//! the floor proof and lives in `crates/worker/tests/oci_provider_live.rs`, which
//! `just oci-live-smoke` selects. Everything in THIS file is a fold
//! over values or a read of a manifest, so it rides `just gate` on any host and
//! reds identically everywhere.
//!
//! An INTEGRATION test rather than an inline module because
//! `std::env::set_var` is `unsafe` under edition 2024 and `kata-worker` keeps
//! its `unsafe` to `process.rs`'s spawn-time kernel calls (see its `lib.rs`).
//! nextest runs each `#[test]` in its own process, so the toggling here cannot
//! race a sibling.

#![allow(unsafe_code)]

use std::path::{Path, PathBuf};

use kata_agent::resource_bounds::ResourceBounds;
use kata_provider_protocol::{
    AssignStage, AssignmentAccepted, AssignmentRefused, CERTIFICATE_VERSION, CertificateVersion,
    ClaimedContainment, FrameError, MAX_FRAME_BYTES, MAX_SUPPORTED_PROTOCOL_VERSION,
    MIN_SUPPORTED_PROTOCOL_VERSION, MeasuredUsernsRestriction, OciBundlePlan, OciMeasuredBasis,
    OciStdio, PROTOCOL_VERSION, PinnedRuntime, ProtocolVersion, ProviderCertificate, ProviderFrame,
    ProviderHello, ProviderRefusal, SUPPORTED_CERTIFICATE_VERSION, StageCompleted, SupervisorFrame,
    admit, body_len, encode_frame, measured_certificate, read_frame,
};
use kata_types::sandbox_seccomp::kata_floor_bpf;
use kata_worker::provider_supervisor::{
    PROVIDER_BINARY_PREFIX, PROVIDER_CGROUP_LEAF, ProviderFloor, ProviderLaunchSpec,
    outer_cgroup_bounds, provider_command_prefix,
};
use kata_worker::sandbox_bounds::{CgroupDelegation, CgroupObservation, fold_cgroup_delegation};
use kata_worker::sandbox_posture::ContainmentLever;
use strum::IntoEnumIterator;

/// The name every fixture below declares, so a mismatch is always deliberate.
const DECLARED: &str = "youki";

/// The repository root, derived rather than typed: `crates/worker` ← `crates` ←
/// root. A hardcoded path would break the moment the crate moved and would break
/// SILENTLY, since a manifest that cannot be read would make the closure test
/// pass by finding no dependencies.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/worker sits two levels below the repository root")
        .to_path_buf()
}

fn hello(protocol: u16, certificate: u16, cert: ProviderCertificate) -> ProviderHello {
    ProviderHello {
        protocol_version: ProtocolVersion(protocol),
        certificate_version: CertificateVersion(certificate),
        certificate: cert,
    }
}

/// The hello carrying [`measured_certificate`] over [`basis`].
fn measured_hello() -> ProviderHello {
    hello(
        PROTOCOL_VERSION.0,
        CERTIFICATE_VERSION.0,
        measured_certificate(DECLARED, basis()),
    )
}

/// A syntactically complete measured basis, for the refusal arms that carry one.
///
/// Literal rather than from `certify_youki`: every test in this file runs on any
/// host, and the properties under test are the LABELS and the fold, both of which
/// are pure over this value. What a REAL basis looks like — and that kata's
/// producer and the provider's echo agree on one — is
/// `crates/worker/tests/oci_provider_live.rs`' subject, on a host that can
/// certify.
fn basis() -> OciMeasuredBasis {
    OciMeasuredBasis {
        youki: PinnedRuntime {
            store_path: "/nix/store/0000000000000000000000000000000-youki/bin/youki".to_owned(),
            sha256: "a".repeat(64),
        },
        youki_version: "0.7.0".to_owned(),
        // The certification that mints a basis refuses `seccomp_unsupported`
        // unless `youki --version` carried this line, so every basis kata
        // measures names a libseccomp.
        libseccomp_version: "2.6.1".to_owned(),
        apparmor_profile_name: "youki".to_owned(),
        apparmor_profile_sha256: "b".repeat(64),
        userns_restriction: MeasuredUsernsRestriction::Restricted,
        delegated_cgroup_parent: None,
        functional_probe_id: "kata-oci-certify-4242".to_owned(),
        residue_denied: true,
    }
}

/// Sets or clears a variable for the life of the guard, restoring what was
/// there.
struct EnvGuard {
    key: &'static str,
    previous: Option<String>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var(key).ok();
        unsafe { std::env::set_var(key, value) };
        Self { key, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => unsafe { std::env::set_var(self.key, value) },
            None => unsafe { std::env::remove_var(self.key) },
        }
    }
}

// ---------------------------------------------------------------------------
// NON-VACUITY FIRST: the fold can say YES.
// ---------------------------------------------------------------------------

/// Every refusal test below is satisfiable by a fold that refuses EVERYTHING, so
/// the admitting arm is asserted before any of them.
///
/// **Would red if:** `admit` grew a condition the shipped certificate cannot
/// satisfy.
#[test]
fn the_measured_provider_is_admitted() {
    let admitted =
        admit(&measured_hello(), DECLARED, Some(&basis())).expect("the shipped measured hello");
    assert_eq!(admitted.protocol_version(), PROTOCOL_VERSION);
    assert_eq!(admitted.certificate_version(), CERTIFICATE_VERSION);
    assert_eq!(
        admitted.certificate().containment,
        ClaimedContainment::ProviderEnforced,
        "the shipped certificate claims provider enforcement, admissible only beside the \
         basis kata measured"
    );
}

// ---------------------------------------------------------------------------
// TWO numbers, and each mismatches ALONE.
// ---------------------------------------------------------------------------

/// The protocol's load-bearing rule is *"they move independently"*, and this
/// is what makes it an observation.
///
/// A build that used ONE number wearing two names would pass any test that
/// mismatched both at once. So each arm moves exactly one number and requires
/// the OTHER half's refusal to be absent — and the third arm pins the ORDER, so
/// a peer that is wrong about both is told about the protocol first (the number
/// that decides whether kata can read the certificate's meaning at all).
///
/// **Would red if:** the two constants were folded into one (the second arm
/// would report `provider_protocol_too_new`), or the certificate check were
/// dropped (the second arm would be `Ok`).
#[test]
fn the_two_version_numbers_mismatch_independently() {
    let protocol_only = admit(
        &hello(
            MAX_SUPPORTED_PROTOCOL_VERSION.0 + 1,
            CERTIFICATE_VERSION.0,
            measured_certificate(DECLARED, basis()),
        ),
        DECLARED,
        // Kata's measurement equals the certificate's: these arms are about the two
        // version numbers, the residue declaration and the announced name, none of
        // which a basis can excuse or condemn.
        Some(&basis()),
    )
    .expect_err("a protocol above the ceiling is refused");
    assert_eq!(
        protocol_only.label(),
        "provider_protocol_too_new",
        "moving ONLY the protocol number must produce the PROTOCOL refusal; got {protocol_only}"
    );

    let certificate_only = admit(
        &hello(
            PROTOCOL_VERSION.0,
            SUPPORTED_CERTIFICATE_VERSION.0 + 1,
            measured_certificate(DECLARED, basis()),
        ),
        DECLARED,
        // Kata's measurement equals the certificate's: these arms are about the two
        // version numbers, the residue declaration and the announced name, none of
        // which a basis can excuse or condemn.
        Some(&basis()),
    )
    .expect_err("a certificate version this build does not read is refused");
    assert_eq!(
        certificate_only.label(),
        "provider_certificate_version_mismatch",
        "moving ONLY the certificate number must produce the CERTIFICATE refusal. If this reads \
         `provider_protocol_too_new`, the two numbers are one number and the independence claim \
         is false; got {certificate_only}"
    );

    let both = admit(
        &hello(
            MAX_SUPPORTED_PROTOCOL_VERSION.0 + 1,
            SUPPORTED_CERTIFICATE_VERSION.0 + 1,
            measured_certificate(DECLARED, basis()),
        ),
        DECLARED,
        // Kata's measurement equals the certificate's: these arms are about the two
        // version numbers, the residue declaration and the announced name, none of
        // which a basis can excuse or condemn.
        Some(&basis()),
    )
    .expect_err("both wrong is still a refusal");
    assert_eq!(
        both.label(),
        "provider_protocol_too_new",
        "a peer wrong about BOTH numbers hears about the protocol first: a certificate decoded \
         under a protocol this build does not implement is a field kata guessed the semantics of"
    );
}

/// The two protocol refusals carry OPPOSITE operator recourse, so they must be
/// two arms.
///
/// **Would red if:** either arm were folded into a single "bad provider protocol
/// version" refusal — half the operators who read it would upgrade the wrong
/// component, which is the defect `FrameRefusal::ProtocolTooNew` was minted for
/// one protocol over.
#[test]
fn too_old_and_too_new_name_opposite_recourse() {
    let too_old = admit(
        &hello(
            MIN_SUPPORTED_PROTOCOL_VERSION.0 - 1,
            CERTIFICATE_VERSION.0,
            measured_certificate(DECLARED, basis()),
        ),
        DECLARED,
        // Kata's measurement equals the certificate's: these arms are about the two
        // version numbers, the residue declaration and the announced name, none of
        // which a basis can excuse or condemn.
        Some(&basis()),
    )
    .expect_err("below the floor is refused");
    assert_eq!(too_old.label(), "provider_protocol_too_old");
    let old_text = too_old.to_string();
    assert!(
        old_text.contains("Upgrade the PROVIDER"),
        "the too-OLD refusal must send the operator to the provider; got {old_text}"
    );
    for recourse in [
        "kata host setup",
        "kata sandbox install-external-provider --name youki",
        "KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS",
    ] {
        assert!(
            old_text.contains(recourse),
            "the too-OLD refusal must name how to re-provision the provider from this build \
             (`{recourse}`); got {old_text}"
        );
    }
    assert!(
        !old_text.contains("linked runtime"),
        "there is no linked runtime to route a node through; got {old_text}"
    );
    assert!(
        !old_text.contains("Upgrade KATA"),
        "and must NOT also name the opposite recourse — two messages that both say everything \
         are two messages that say nothing; got {old_text}"
    );

    let too_new = admit(
        &hello(
            MAX_SUPPORTED_PROTOCOL_VERSION.0 + 1,
            CERTIFICATE_VERSION.0,
            measured_certificate(DECLARED, basis()),
        ),
        DECLARED,
        // Kata's measurement equals the certificate's: these arms are about the two
        // version numbers, the residue declaration and the announced name, none of
        // which a basis can excuse or condemn.
        Some(&basis()),
    )
    .expect_err("above the ceiling is refused");
    let new_text = too_new.to_string();
    assert!(
        new_text.contains("Upgrade KATA"),
        "the too-NEW refusal must send the operator to kata; got {new_text}"
    );
    assert!(
        !new_text.contains("Upgrade the PROVIDER"),
        "and must not also name the opposite recourse; got {new_text}"
    );
}

/// The exact boundaries, because that is where an off-by-one lives.
#[test]
fn the_protocol_boundaries_are_inclusive_on_both_sides() {
    assert!(
        admit(
            &hello(
                MIN_SUPPORTED_PROTOCOL_VERSION.0,
                CERTIFICATE_VERSION.0,
                measured_certificate(DECLARED, basis())
            ),
            DECLARED,
            Some(&basis())
        )
        .is_ok(),
        "exactly the minimum is SUPPORTED, not refused"
    );
    assert!(
        admit(
            &hello(
                MAX_SUPPORTED_PROTOCOL_VERSION.0,
                CERTIFICATE_VERSION.0,
                measured_certificate(DECLARED, basis())
            ),
            DECLARED,
            Some(&basis())
        )
        .is_ok(),
        "exactly the ceiling is SUPPORTED, not refused"
    );
}

// ---------------------------------------------------------------------------
// The certificate's CONTENT — what a provider may claim.
// ---------------------------------------------------------------------------

/// A provider claiming to enforce containment kata never measured is REFUSED.
///
/// At the certificate layer: kata has measured nothing about a process
/// it does not link, so admitting the claim is how an operator obtains a
/// containment verdict nobody established. A provider whose own containment
/// kata DID measure (`kata-provider-youki`) is admitted by ADDING that
/// measurement (`OciMeasuredBasis`), never by relaxing this.
///
/// **Would red if:** the containment check were dropped, or
/// `ClaimedContainment::ProviderEnforced` were made admissible without a
/// measurement beside it.
#[test]
fn a_provider_claiming_containment_kata_never_measured_is_refused() {
    let refusal = admit(
        &hello(
            PROTOCOL_VERSION.0,
            CERTIFICATE_VERSION.0,
            ProviderCertificate {
                provider: DECLARED.to_owned(),
                containment: ClaimedContainment::ProviderEnforced,
                declares_construction_residue_unverified: true,
                // No basis: this arm is the unmeasured-claim refusal, which is what
                // `admit` must still produce where kata measured nothing.
                measured_basis: None,
            },
        ),
        DECLARED,
        // Kata measured NO rootless-OCI basis: that is this arm's premise.
        None,
    )
    .expect_err("a claimed-containment provider is refused");
    assert_eq!(
        refusal.label(),
        "provider_claimed_containment_is_unmeasured"
    );
    assert!(
        refusal.to_string().contains("measured NOTHING"),
        "the refusal must say why — that kata measured nothing — rather than restating the \
         variant name; got {refusal}"
    );
}

/// Unverified residue, made structural: a certificate must DECLARE that kata
/// did not verify its construction residue.
///
/// A certificate may say kata did not
/// verify the 13 `ConstructionResidue` syscalls, and may NOT launder the
/// provider's assertion into a kata measurement. A provider that declares
/// `false` here is asserting something about KATA, and it is refused by name.
///
/// **Would red if:** the field were dropped, or defaulted, or the check removed
/// — each of which would let a provider ship a certificate that reads as though
/// kata had verified something it structurally cannot.
#[test]
fn a_provider_claiming_kata_verified_its_construction_residue_is_refused() {
    let refusal = admit(
        &hello(
            PROTOCOL_VERSION.0,
            CERTIFICATE_VERSION.0,
            ProviderCertificate {
                provider: DECLARED.to_owned(),
                containment: ClaimedContainment::ProviderEnforced,
                declares_construction_residue_unverified: false,
                measured_basis: Some(basis()),
            },
        ),
        DECLARED,
        // Kata's measurement equals the certificate's: these arms are about the two
        // version numbers, the residue declaration and the announced name, none of
        // which a basis can excuse or condemn.
        Some(&basis()),
    )
    .expect_err("a residue-verification claim is refused");
    assert_eq!(refusal.label(), "provider_residue_verification_claimed");
    assert!(
        refusal
            .to_string()
            .contains("Set `declares_construction_residue_unverified` to true"),
        "the refusal must name the field the provider has to set; got {refusal}"
    );
}

/// A binary that answers to one name and announces another is a SUBSTITUTION.
///
/// **Would red if:** the identity check were dropped — an operator declaring
/// `youki` would then be served by whatever binary answered to that
/// name, with the certificate's own `provider` field unread.
#[test]
fn a_provider_announcing_a_different_name_is_refused() {
    let refusal = admit(&measured_hello(), "something-else", Some(&basis()))
        .expect_err("the announced name must match the declared one");
    assert_eq!(refusal.label(), "provider_identity_mismatch");
}

// ---------------------------------------------------------------------------
// Labels.
// ---------------------------------------------------------------------------

/// One label per refusal, and the enumeration is exhaustive by CONSTRUCTION.
///
/// The `match` below is over a value of the enum with no wildcard arm, so a
/// new variant is `E0004` here rather than a label nobody checked. That is
/// the dummy-exhaustive-match idiom, chosen over
/// `axis_domain!` because that macro lives in a
/// `#[cfg(test)] mod tests` and is not reachable cross-crate.
#[test]
fn every_provider_refusal_has_its_own_label() {
    let all = [
        ProviderRefusal::ProtocolTooOld {
            claimed: ProtocolVersion(0),
            minimum: MIN_SUPPORTED_PROTOCOL_VERSION,
        },
        ProviderRefusal::ProtocolTooNew {
            claimed: ProtocolVersion(99),
            supported: MAX_SUPPORTED_PROTOCOL_VERSION,
        },
        ProviderRefusal::CertificateVersionMismatch {
            claimed: CertificateVersion(99),
            supported: SUPPORTED_CERTIFICATE_VERSION,
        },
        ProviderRefusal::ClaimedContainmentIsUnmeasured {
            claimed: ClaimedContainment::ProviderEnforced,
        },
        ProviderRefusal::ResidueVerificationClaimed,
        // `ClaimedContainment::ProviderEnforced` is admissible only BESIDE a kata
        // measurement, and each way that pairing can be wrong needs its own name:
        // kata measured one and the certificate names none, or the two disagree.
        ProviderRefusal::MeasuredBasisAbsent,
        ProviderRefusal::MeasuredBasisDisagrees {
            measured: Box::new(basis()),
            announced: Box::new(OciMeasuredBasis {
                youki_version: "0.6.0".to_owned(),
                ..basis()
            }),
        },
        ProviderRefusal::ProviderIdentityMismatch {
            declared: DECLARED.to_owned(),
            announced: "other".to_owned(),
        },
    ];
    // Closed-world anchor: adding a variant makes this match non-exhaustive.
    for refusal in &all {
        match refusal {
            ProviderRefusal::ProtocolTooOld { .. }
            | ProviderRefusal::ProtocolTooNew { .. }
            | ProviderRefusal::CertificateVersionMismatch { .. }
            | ProviderRefusal::ClaimedContainmentIsUnmeasured { .. }
            | ProviderRefusal::ResidueVerificationClaimed
            | ProviderRefusal::MeasuredBasisAbsent
            | ProviderRefusal::MeasuredBasisDisagrees { .. }
            | ProviderRefusal::ProviderIdentityMismatch { .. } => {}
        }
    }
    let labels: std::collections::BTreeSet<&str> = all.iter().map(ProviderRefusal::label).collect();
    assert_eq!(
        labels.len(),
        all.len(),
        "two refusals share a label, so an operator cannot tell them apart in a log: {labels:?}"
    );
    for refusal in &all {
        assert!(
            refusal.to_string().len() > 40,
            "every refusal must SAY something an operator can act on; `{}` says {refusal:?}",
            refusal.label()
        );
    }
}

/// Two protocols, two version numbers, two refusal vocabularies — and an
/// operator must never read one as the other.
///
/// `kata_core::operational::ingress_fence::FrameRefusal::ProtocolTooNew` fences
/// the WORKER/ATTEMPT wire; `ProviderRefusal::ProtocolTooNew` fences the
/// PROVIDER wire. They mean different upgrades of different components. Sharing
/// the token `protocol_too_new` would be briefing defect class (d) at the exact
/// place it costs an outage.
///
/// **Would red if:** the `provider_` prefix were dropped from this protocol's
/// labels.
#[test]
fn the_provider_refusal_labels_cannot_be_confused_with_the_attempt_fences() {
    let attempt = kata_core::operational::ingress_fence::FrameRefusal::ProtocolTooNew {
        claimed: 99,
        supported: 1,
    };
    let provider = ProviderRefusal::ProtocolTooNew {
        claimed: ProtocolVersion(99),
        supported: MAX_SUPPORTED_PROTOCOL_VERSION,
    };
    assert_ne!(
        attempt.as_str(),
        provider.label(),
        "the attempt fence and the provider handshake must not share a refusal token: both read \
         `{}`",
        provider.label()
    );
    assert!(
        provider.label().starts_with("provider_"),
        "every provider-protocol refusal token is prefixed so the two vocabularies cannot \
         collide as either grows; got `{}`",
        provider.label()
    );
}

// ---------------------------------------------------------------------------
// The codec.
// ---------------------------------------------------------------------------

/// Every frame in both directions survives a round trip through the real codec.
///
/// **Would red if:** a frame's serde attributes drifted so a field was renamed
/// on the wire but not on the way back.
#[test]
fn every_frame_round_trips_through_the_real_codec() {
    let provider_frames = [
        ProviderFrame::Hello(measured_hello()),
        ProviderFrame::Accepted(AssignmentAccepted {
            assignment_id: "01J".to_owned(),
        }),
        ProviderFrame::Completed(StageCompleted {
            assignment_id: "01J".to_owned(),
            exit_code: Some(0),
            // v6: the frame carries SIZES, not the bytes — the bytes live in
            // the spool files the assignment's `capture` named.
            stdout_bytes: 3,
            stderr_bytes: 3,
            capture_exceeded: false,
        }),
        ProviderFrame::Refused(AssignmentRefused {
            assignment_id: "01J".to_owned(),
            reason: "no such program".to_owned(),
        }),
    ];
    for frame in &provider_frames {
        let bytes = encode_frame(frame).expect("encode");
        let mut cursor = std::io::Cursor::new(bytes);
        let back: ProviderFrame = read_frame(&mut cursor).expect("decode");
        assert_eq!(
            &back, frame,
            "a provider frame did not survive a round trip"
        );
    }

    // The assignment round-trips with its plan populated. (The plan's own round
    // trip is the protocol crate's `the_oci_plan_is_the_only_plan_on_the_wire`.)
    {
        let plan = OciBundlePlan {
            config_json: r#"{"ociVersion":"1.0.2"}"#.to_owned(),
            rootfs_mountpoints: vec!["/work".to_owned()],
            container_id: "kata-roundtrip".to_owned(),
            youki: basis().youki,
            cgroup_parent: None,
            state_root: "/var/lib/kata/attempts/roundtrip/oci".to_owned(),
            stdio: OciStdio::Captured,
            egress_hook: None,
        };
        let assign = SupervisorFrame::Assign(AssignStage {
            protocol_version: PROTOCOL_VERSION,
            assignment_id: "01J".to_owned(),
            plan,
            capture: kata_provider_protocol::CaptureSpec {
                spool_dir: "/tmp/kata-stage-capture".to_owned(),
                limit_bytes: 1_048_576,
            },
        });
        let bytes = encode_frame(&assign).expect("encode");
        let mut cursor = std::io::Cursor::new(bytes);
        let back: SupervisorFrame = read_frame(&mut cursor).expect("decode");
        assert_eq!(back, assign, "an assignment did not survive a round trip");
    }
}

/// The length prefix is the ONE place a peer chooses kata's allocation, so both
/// of its bounds are refusals rather than reads.
///
/// **Would red if:** the zero check were dropped (an empty body would be read as
/// a frame that said nothing) or the ceiling raised to `u32::MAX` (a four-byte
/// header would become a 4 GiB allocation any peer could demand).
#[test]
fn the_length_prefix_refuses_zero_and_refuses_the_unbounded() {
    assert!(
        matches!(body_len([0, 0, 0, 0]), Err(FrameError::EmptyBody)),
        "a zero-length body is a refusal"
    );
    let over = u32::try_from(MAX_FRAME_BYTES + 1).expect("the ceiling plus one fits u32");
    assert!(
        matches!(
            body_len(over.to_be_bytes()),
            Err(FrameError::BodyTooLarge { .. })
        ),
        "a body above the ceiling is a refusal"
    );
    let exact = u32::try_from(MAX_FRAME_BYTES).expect("the ceiling fits u32");
    assert_eq!(
        body_len(exact.to_be_bytes()).expect("exactly the ceiling is accepted"),
        MAX_FRAME_BYTES,
        "the boundary is INCLUSIVE, which is where an off-by-one would live"
    );
}

/// An unknown field is a REFUSAL, not a silent drop.
///
/// Exhaustive destructures at every decode mean a field ADDED
/// by this build cannot be dropped; `deny_unknown_fields` is the other
/// direction — a field a NEWER peer added cannot be ignored by an older kata
/// that would then act on a frame it only half understood.
///
/// **Would red if:** `#[serde(deny_unknown_fields)]` came off any frame struct.
#[test]
fn an_unknown_frame_field_is_refused_rather_than_dropped() {
    let body = br#"{"kind":"accepted","frame":{"assignment_id":"01J","urgency":"high"}}"#;
    let refused: Result<ProviderFrame, _> = kata_provider_protocol::decode_frame(body);
    let err = refused.expect_err("an unknown field must be refused");
    assert!(
        matches!(err, FrameError::Malformed(_)),
        "an unknown field is a malformed frame for this protocol version; got {err}"
    );

    // Non-vacuity: the SAME body without the extra field must decode, so the
    // refusal above is about the field and not about the shape.
    let ok: ProviderFrame = kata_provider_protocol::decode_frame(
        br#"{"kind":"accepted","frame":{"assignment_id":"01J"}}"#,
    )
    .expect("the same frame without the unknown field decodes");
    assert_eq!(
        ok,
        ProviderFrame::Accepted(AssignmentAccepted {
            assignment_id: "01J".to_owned()
        })
    );
}

/// A stream that ends where a frame was expected is a CRASH, reported as one.
///
/// **Would red if:** the reader returned `Ok(None)`-shaped silence for a closed
/// peer — *"the provider produced no answer"* and *"the provider produced an
/// empty answer"* are different facts and only one of them is a crash.
#[test]
fn a_closed_stream_is_reported_as_a_closed_stream() {
    let mut empty = std::io::Cursor::new(Vec::new());
    let err = read_frame::<_, ProviderFrame>(&mut empty).expect_err("EOF is not a frame");
    assert!(
        matches!(err, FrameError::PeerClosed),
        "a clean EOF where a header was expected is `PeerClosed`; got {err}"
    );

    // A TRUNCATED header is a different fact from a closed stream, and must not
    // fold into it.
    let mut partial = std::io::Cursor::new(vec![0u8, 0u8]);
    let err =
        read_frame::<_, ProviderFrame>(&mut partial).expect_err("half a header is not a frame");
    assert!(
        matches!(err, FrameError::Io(_)),
        "a truncated header is an I/O fact, not a clean close; got {err}"
    );
}

// ---------------------------------------------------------------------------
// The floor invariant — no operator can ask for an unfloored provider.
// ---------------------------------------------------------------------------

fn production_spec() -> ProviderLaunchSpec {
    ProviderLaunchSpec::production(
        PathBuf::from("/nonexistent/kata-provider-absent"),
        DECLARED,
        std::time::Duration::from_secs(60),
    )
}

/// The PRODUCTION launch spec always carries the shipped floor, read back off
/// the prefix that would be spawned.
///
/// **Would red if:** `ProviderLaunchSpec::production` stopped setting
/// `ProviderFloor::Installed`, or `provider_command_prefix` stopped putting the
/// bytes on the field. Neither is visible in argv — a `pre_exec` floor emits
/// none — so this reads the field, which is the only host-independent
/// observation that exists.
#[test]
fn the_production_provider_prefix_always_carries_the_shipped_floor() {
    let prefix = provider_command_prefix(&production_spec(), ResourceBounds::default());
    let floor = kata_floor_bpf();
    assert!(!floor.is_empty(), "the shipped floor must be non-empty");
    assert_eq!(
        prefix.kata_floor_bpf.as_deref(),
        Some(floor.as_slice()),
        "the production provider prefix must carry the SHIPPED floor byte for byte"
    );
}

/// **Measured rather than asserted: no operator knob can null the
/// provider's floor.**
///
/// Every `ContainmentLever` is set in turn — the closed, `strum::EnumIter`
/// surface that is the whole of this node's containment configuration — and the
/// production prefix's floor must not move by one byte.
///
/// **Would red if:** any lever were wired into `kata_floor_bpf()` or into
/// `ProviderFloor::bytes`, which is exactly the forbidden change: an
/// operator able to ask for an unfloored external provider would defeat the
/// entire security argument for an external provider from one environment variable.
#[test]
fn no_containment_lever_can_null_the_provider_floor() {
    let baseline = provider_command_prefix(&production_spec(), ResourceBounds::default())
        .kata_floor_bpf
        .expect("the production prefix is floored before any lever is set");
    let mut levers = 0usize;
    for lever in ContainmentLever::iter() {
        levers += 1;
        let _guard = EnvGuard::set(lever.env(), "1");
        let under_lever = provider_command_prefix(&production_spec(), ResourceBounds::default())
            .kata_floor_bpf
            .unwrap_or_else(|| {
                panic!(
                    "`{}=1` produced an UNFLOORED external provider. That must be \
                     unreachable from any knob.",
                    lever.env()
                )
            });
        assert_eq!(
            under_lever,
            baseline,
            "`{}=1` moved the kata seccomp floor on the provider spawn",
            lever.env()
        );
    }
    assert!(
        levers >= 3,
        "the lever sweep saw only {levers} levers; a sweep over an empty or shrunken enum would \
         pass by having no subject"
    );
}

/// The floor-absent arm exists, is reachable ONLY by naming it, and is what
/// the floor proof's control is built from.
///
/// **Would red if:** the two arms produced the same bytes — the control would
/// then be the floored arm under another name and the floor proof would compare a thing
/// with itself.
#[test]
fn the_proof_control_arm_is_the_only_route_to_a_floorless_provider_prefix() {
    let mut spec = production_spec();
    spec.floor = ProviderFloor::AbsentForProofControl;
    let control = provider_command_prefix(&spec, ResourceBounds::default());
    assert!(
        control.kata_floor_bpf.is_none(),
        "the control arm must carry NO floor, else the floor proof's non-vacuity control is the floored \
         arm wearing a different name"
    );
    // Closed-world anchor over the two arms.
    for arm in [
        ProviderFloor::Installed,
        ProviderFloor::AbsentForProofControl,
    ] {
        match arm {
            ProviderFloor::Installed | ProviderFloor::AbsentForProofControl => {}
        }
    }
    assert_eq!(ProviderFloor::Installed.label(), "installed");
    assert_eq!(
        ProviderFloor::AbsentForProofControl.label(),
        "absent_for_proof_control",
        "the control arm's token must SAY it is a control, so an evidence line carrying it cannot \
         be read as a production spawn"
    );
}

// ---------------------------------------------------------------------------
// Resolution and the outer cgroup.
// ---------------------------------------------------------------------------

/// **There is no `PATH` resolution, and this is the structural proof.**
///
/// A provider is identified by content, so `PATH` resolution is refused, and
/// resolution by filesystem location with it. No function performs one —
/// `resolve_provider_binary` and `resolve_declared_provider_binary` are the
/// names such a function would carry, and this test refuses both.
///
/// This module resolves nothing: it is handed a
/// `ProviderLaunchSpec::binary` and spawns it.
/// `kata_worker::provider_store::ProviderStore::resolve` is the only resolver,
/// and `crates/worker/tests/provider_store.rs` is where it is proven.
///
/// **Would red if:** either function came back, under its own name or another.
/// A grep-shaped assertion rather than a call-shaped one is deliberate: the
/// property is an ABSENCE, and an absence cannot be observed by calling
/// something.
#[test]
fn the_supervisor_module_resolves_nothing_and_reads_no_path() {
    let source =
        std::fs::read_to_string(repo_root().join("crates/worker/src/provider_supervisor.rs"))
            .expect("the supervisor source is readable");
    // NON-VACUITY first: this assertion is satisfiable by reading the wrong
    // file, or by a file that shrank to nothing.
    assert!(
        source.contains("pub async fn launch(spec: &ProviderLaunchSpec)"),
        "sanity: this must be the supervisor's own source, else every absence below is an \
         absence in a file nobody cares about"
    );
    assert!(
        !source.contains("var_os(\"PATH\")") && !source.contains("var(\"PATH\")"),
        "the supervisor read `PATH` to resolve a provider, which kata refuses: the resolver \
         would read the environment of whatever process the worker happens to be, so one node \
         resolves different bytes as its environment changes — and the environment of a \
         worker loop embedded in the main is not the environment of the standalone \
         `kata-worker`."
    );
    for gone in [
        "fn resolve_provider_binary",
        "fn resolve_declared_provider_binary",
    ] {
        assert!(
            !source.contains(gone),
            "`{gone}` exists. A provider resolver by location must not exist at all, \
             because a deprecated resolver is still a resolver an operator's node can reach."
        );
    }
    // And the CONVENTION survives, because it is what picks the executable
    // inside a resolved store entry. Without this the assertions above are
    // satisfiable by deleting the naming rule too, which would be a different
    // (and unshipped) design.
    assert_eq!(PROVIDER_BINARY_PREFIX, "kata-provider-");
}

/// The outer cgroup is planned ONLY from a MEASURED delegation.
///
/// A directory's existence read as "cgroup delegation: present" can be wrong in
/// either direction.
///
/// **Would red if:** `outer_cgroup_bounds` planned a cgroup from anything but
/// `usable_parent` — a plan under an unwritable parent would fail every provider
/// spawn CLOSED, because `attach_resource_bounds` refuses to launch a stage
/// whose requested bound could not be created.
#[test]
fn the_outer_cgroup_is_planned_only_from_a_measured_delegation() {
    // EXHAUSTIVE literal, deliberately: a new `CgroupObservation` field must be
    // re-decided here rather than absorbed by a spread, because this fixture is
    // the "measured NOTHING" arm and a defaulted field is exactly how it would
    // quietly become the "measured something" arm.
    let nothing_measured = CgroupObservation {
        unified_hierarchy: false,
        own_cgroup: Err("this fixture measured nothing".to_owned()),
        offered: std::collections::BTreeSet::new(),
        enabled_for_children: std::collections::BTreeSet::new(),
        scratch_mkdir: Err("this fixture never attempted a mkdir".to_owned()),
        round_trips: std::collections::BTreeMap::new(),
        relocated_self: false,
        subtree_enables: std::collections::BTreeMap::new(),
        swap_cap: None,
    };
    let unusable: CgroupDelegation = fold_cgroup_delegation(nothing_measured);
    assert!(
        unusable.usable_parent.is_none(),
        "a default observation measured nothing, so it must yield no usable parent"
    );
    assert!(
        outer_cgroup_bounds(&unusable, DECLARED, 0).is_empty(),
        "no measurement, no cgroup, and no bound requested — an empty ResourceBounds is what \
         `attach_resource_bounds` reads as `nothing to do`"
    );

    // The positive arm, synthesized: a delegation whose parent WAS measured
    // usable must produce a plan under exactly that parent. Without this the
    // assertion above is satisfiable by a function that always returns empty.
    let mut usable = unusable;
    usable.usable_parent = Some(PathBuf::from("/sys/fs/cgroup/kata.test"));
    let bounds = outer_cgroup_bounds(&usable, DECLARED, 7);
    let plan = bounds
        .cgroup
        .as_ref()
        .expect("a measured-usable delegation plans an outer cgroup");
    // TWO LEVELS: the SWEEP ROOT is the plan's parent —
    // `<usable parent>/kata.provider.<name>.<pid>.<sequence>` — and the provider itself goes
    // in a `provider` leaf beneath it, so the swept cgroup has no member process
    // and can distribute controllers to the per-container parents the rootless-OCI
    // route creates beside it. MEASURED: a container leaf nested under a cgroup
    // that holds a process cannot be populated at all (`EOPNOTSUPP` on
    // `cgroup.procs`), which is what forces the extra level.
    assert_eq!(
        plan.parent.parent(),
        Some(Path::new("/sys/fs/cgroup/kata.test")),
        "the sweep root must be created directly under the MEASURED usable parent; got {}",
        plan.parent.display()
    );
    assert!(
        plan.parent
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("kata.provider.")),
        "an OUTER provider subtree must be distinguishable from the per-stage cgroups in \
         `systemd-cgls`; got {}",
        plan.parent.display()
    );
    // ONE ROOT PER LAUNCH. A name that stopped at the pid made a supervisor dropped
    // mid-stage (whose `Drop` kills but cannot remove) wedge every later launch on the
    // worker with `already exists`.
    assert_eq!(
        plan.parent.file_name().and_then(|n| n.to_str()),
        Some(format!("kata.provider.{DECLARED}.{}.7", std::process::id()).as_str()),
        "the sweep root is named `kata.provider.<name>.<pid>.<sequence>`"
    );
    assert_ne!(
        outer_cgroup_bounds(&usable, DECLARED, 8)
            .cgroup
            .map(|p| p.parent),
        Some(plan.parent.clone()),
        "two launches in one worker must never name one sweep root"
    );
    assert_eq!(
        plan.name, PROVIDER_CGROUP_LEAF,
        "the provider goes in a LEAF of the sweep root, not in the sweep root itself: a swept \
         cgroup with a member process is a `domain invalid` parent, and no container leaf can be \
         populated beneath it"
    );
    assert_eq!(
        plan.path(),
        PathBuf::from("/sys/fs/cgroup/kata.test")
            .join(plan.parent.file_name().expect("the sweep root is named"))
            .join(PROVIDER_CGROUP_LEAF),
        "the provider's own cgroup is the sweep root's `provider` child"
    );
}

// ---------------------------------------------------------------------------
// The provider is NOT linked into kata.
// ---------------------------------------------------------------------------

/// Every internal (`kata-*`) dependency named by a manifest, as `name` strings.
fn internal_dependencies(manifest: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(manifest)
        .unwrap_or_else(|e| panic!("{} must be readable: {e}", manifest.display()));
    let mut found = Vec::new();
    let mut in_deps = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_deps = trimmed.contains("dependencies");
            continue;
        }
        if !in_deps || trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        let name = trimmed.split(['=', ' ', '.']).next().unwrap_or_default();
        if name.starts_with("kata-") {
            found.push(name.to_owned());
        }
    }
    found
}

/// **The wire crate an external provider shares with kata is an ABSOLUTE LEAF.**
///
/// A provider kata does not link may share the WIRE with it and nothing else.
/// If the wire crate linked `kata-worker`, every provider built on it would link
/// kata too, and the floor proof would be a statement about one process image
/// rather than about a HANDOFF to a process kata does not link.
///
/// **Would red if:** anyone added `kata-types`, `kata-worker`, `kata-agent*` or
/// `kata-core` to the wire crate's manifest. Measured by reading the manifest
/// rather than by `cargo tree` because the closure is its own `[dependencies]`
/// section, so the manifest read is COMPLETE — and it costs no build.
#[test]
fn the_wire_crate_is_an_absolute_leaf() {
    let root = repo_root();
    let protocol = root.join("crates/provider-protocol/Cargo.toml");

    let protocol_deps = internal_dependencies(&protocol);
    assert!(
        protocol_deps.is_empty(),
        "the wire crate must be an absolute leaf — a provider author reimplementing it in another \
         language needs the frame table and no Rust at all. Found: {protocol_deps:?}"
    );

    // NON-VACUITY: the same reader must SEE dependencies where there are some,
    // else the assertion above is satisfied by a parser that finds nothing.
    let worker_deps = internal_dependencies(&root.join("crates/worker/Cargo.toml"));
    assert!(
        worker_deps.contains(&"kata-provider-protocol".to_owned()),
        "kata-worker depends on the wire crate and the reader must see it; found {worker_deps:?}"
    );
    assert!(
        worker_deps.len() > 3,
        "the manifest reader found only {} internal dependencies in kata-worker's manifest, so it \
         is not reading manifests and the assertion above proves nothing",
        worker_deps.len()
    );
}

/// The OCI provider does not link kata: it depends on the wire crate alone, and
/// the temptation there is the sharpest.
///
/// `kata_worker::oci_bundle::materialize_bundle` already writes a plan's bundle and
/// `kata_worker::oci_runtime::run_bundle` already launches one. Either call would
/// make `bin/kata-provider-youki` a re-entry into kata's own launch path, and the
/// claim — that a process kata does not link starts the container kata
/// planned from the FRAME alone — would be a claim about one process image.
///
/// **Would red if:** the provider gained `kata-worker`, `kata-types` or any other
/// internal crate; and the non-vacuity half reds if this reader is pointed at the
/// wrong file.
#[test]
fn the_oci_provider_does_not_link_kata() {
    let root = repo_root();
    let manifest = root.join("bin/kata-provider-youki/Cargo.toml");
    let deps = internal_dependencies(&manifest);
    assert_eq!(
        deps,
        vec!["kata-provider-protocol".to_owned()],
        "the OCI provider may depend on the WIRE and on nothing else of kata's. `materialize_bundle` \
         and `run_bundle` are both one `use` away and both would dissolve the proof. Found: {deps:?}"
    );

    // NON-VACUITY: three non-kata dependencies must be visible in the same file,
    // else "only the wire" is satisfied by a parser that found nothing in a file it
    // failed to open. Each is unavoidable and none is kata's: the basis argv is
    // JSON, re-deriving a pinned digest is a hash, and a SIGTERM handler plus a
    // `kill(2)` is how any provider in any language reaches the kernel.
    let text = std::fs::read_to_string(&manifest).expect("the manifest is readable");
    for line in [
        "serde_json.workspace = true",
        "sha2.workspace = true",
        "libc.workspace = true",
    ] {
        assert!(
            text.contains(line),
            "the OCI provider's manifest no longer declares `{line}`; if that is gone, the reader \
             above is reading the wrong file"
        );
    }
}

/// The OCI provider writes stderr through its non-panicking `note!` and NOTHING else.
///
/// The leak this pins was measured: a supervisor `SIGTERM`ed
/// with its process group loses the reader of the provider's stderr, the provider's
/// cancellation path announces itself with `eprintln!` BEFORE tearing down, the
/// write fails with `EPIPE`, `eprintln!` panics, and the provider dies with its
/// container running. With the write made non-panicking nothing leaked. A panicking
/// write macro anywhere in the file is one refactor away from sitting on a teardown
/// path again, so the check is file-wide.
///
/// **Would red if:** an `eprintln!`, `eprint!`, `println!` or `print!` reappeared in
/// `bin/kata-provider-youki/src/main.rs` (stdout is the frame stream besides, so a
/// `println!` there would also desynchronise every frame after it).
#[test]
fn the_oci_provider_cannot_panic_on_a_lost_stderr() {
    let path = repo_root().join("bin/kata-provider-youki/src/main.rs");
    let source = std::fs::read_to_string(&path).expect("the provider source is readable");
    let offenders: Vec<String> = source
        .lines()
        .enumerate()
        .filter(|(_, line)| {
            let code = line.split("//").next().unwrap_or("");
            ["eprintln!(", "eprint!(", "println!(", "print!("]
                .iter()
                .any(|m| code.contains(m))
        })
        .map(|(n, line)| format!("  line {}: {}", n + 1, line.trim()))
        .collect();
    // NON-VACUITY: the file really writes stderr, through the macro.
    assert!(
        source.contains("note!("),
        "the provider source has no `note!(` call, so this scan is reading the wrong file"
    );
    assert!(
        offenders.is_empty(),
        "the OCI provider uses a PANICKING write macro, which on a lost stderr kills the provider \
         mid-teardown with its container running. Use `note!`:\n{}",
        offenders.join("\n"),
    );
}

// ---------------------------------------------------------------------------
// The frame budget is the stage's own wall clock — never a supervisor constant.
// ---------------------------------------------------------------------------

/// A capsule whose hashed wall clock is W is awaited for W plus
/// `PROVIDER_FRAME_MARGIN` — on the capsule route's production spec, for a W longer
/// than 120 s, and for a W
/// shorter than it (so the budget is DERIVED, not a floor that happens to be large).
///
/// **Would red if:** `ProviderLaunchSpec::production` used a constant frame
/// budget, or `capsule_provider_spec` stopped handing it the capsule's `wall_time_ms`.
#[test]
fn a_capsule_provider_waits_the_capsules_own_wall_clock() {
    use kata_worker::provider_supervisor::PROVIDER_FRAME_MARGIN;
    for wall_time_ms in [180_000_u64, 5_000] {
        let budgets = kata_types::execution_contract::CapsuleBudgets {
            wall_time_ms,
            output_bytes: 1 << 20,
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
            result_bytes: 1 << 20,
            result_entries: 64,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        };
        let spec = kata_worker::oci_driver::capsule_provider_spec(
            PathBuf::from("/nonexistent/kata-provider-youki"),
            budgets,
            &basis(),
        );
        let wall = std::time::Duration::from_millis(wall_time_ms);
        assert!(
            spec.stage_timeout >= wall,
            "{:?} < {wall:?}",
            spec.stage_timeout
        );
        assert_eq!(spec.stage_timeout, wall + PROVIDER_FRAME_MARGIN);
        assert_eq!(
            spec.measured_basis,
            Some(basis()),
            "the ADMITTED basis rides along"
        );
    }
}

/// A supervised provider is held to the stage contract's own wall clock plus
/// the frame margin — never a supervisor constant.
///
/// **Would red if:** `ProviderLaunchSpec::production` went back to a constant.
#[test]
fn a_supervised_provider_waits_the_stages_own_timeout() {
    use kata_worker::provider_supervisor::PROVIDER_FRAME_MARGIN;
    let three_minutes = std::time::Duration::from_millis(180_000);
    let spec = ProviderLaunchSpec::production(
        PathBuf::from("/nonexistent/kata-provider-absent"),
        DECLARED,
        three_minutes,
    );
    assert_eq!(spec.stage_timeout, three_minutes + PROVIDER_FRAME_MARGIN);
}
