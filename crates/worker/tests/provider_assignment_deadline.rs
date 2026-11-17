//! The provider supervisor holds ONE ASSIGNMENT to ONE DEADLINE: the `Assign` write, the
//! acceptance and the terminal frame together end no later than `stage_timeout` after the
//! assignment began — never a fresh budget per read.
//!
//! # Why it matters
//!
//! `kata_types::capsule_timing` derives the main's wall-time grace from the worker's kill
//! firing at the latest `PROVIDER_FRAME_MARGIN` past the capsule's `wall_time_ms`, counted
//! from the assignment. With a budget per read the kill could come at twice that — the
//! acceptance read's whole budget and then the completion read's — and a provider that
//! stopped reading its stdin held the `Assign` write forever.
//!
//! # The instrument
//!
//! A FAKE provider: a shell script that replays pre-encoded frames (a hello kata admits, then
//! an acceptance and a terminal frame, each after a delay it waits out on its own clock).
//! Nothing here needs a delegated cgroup or a container runtime: the launch installs the
//! kata floor (a seccomp filter any Linux process may load) and the supervisor's outer
//! cgroup is simply absent on a host that delegates none. Host-free; rides `just gate`.
//!
//! The same instrument also replays a hello kata must REFUSE, for the one handshake
//! property that needs a real supervisor read: the opening frame's version numbers are
//! judged before its body, so a provider speaking another certificate vocabulary is refused
//! by name rather than as an undecodable frame, and an assignment too large to frame, for the
//! one supervisor site that words a codec refusal on the WRITE side.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kata_provider_protocol::{
    AssignmentAccepted, CERTIFICATE_VERSION, CertificateVersion, MeasuredUsernsRestriction,
    OciBundlePlan, OciMeasuredBasis, OciStdio, PROTOCOL_VERSION, PinnedRuntime, ProviderFrame,
    ProviderHello, StageCompleted, encode_frame, measured_certificate,
};
use kata_worker::provider_supervisor::{ProviderLaunchSpec, ProviderSupervisor, StageAssignment};

const NAME: &str = "deadline-fixture";
const ASSIGNMENT: &str = "deadline-assignment";

/// The measured basis the supervisor hands the fake and the fake's hello echoes. Literal:
/// these cells run on any host, and the property under test is the frame budget.
fn basis() -> OciMeasuredBasis {
    OciMeasuredBasis {
        youki: PinnedRuntime {
            store_path: "/nix/store/0000000000000000000000000000000-youki/bin/youki".to_owned(),
            sha256: "a".repeat(64),
        },
        youki_version: "0.7.0".to_owned(),
        libseccomp_version: "2.6.1".to_owned(),
        apparmor_profile_name: "youki".to_owned(),
        apparmor_profile_sha256: "b".repeat(64),
        userns_restriction: MeasuredUsernsRestriction::Restricted,
        delegated_cgroup_parent: None,
        functional_probe_id: "kata-oci-certify-4242".to_owned(),
        residue_denied: true,
    }
}

/// Write `frame`'s encoded bytes to `dir/<file>` and return the path.
fn frame_file(dir: &Path, file: &str, frame: &ProviderFrame) -> PathBuf {
    let path = dir.join(file);
    std::fs::write(
        &path,
        encode_frame(frame).expect("the fixture frame encodes"),
    )
    .expect("the frame file is written");
    path
}

/// Provision the fake provider: `body` runs after the hello is written, with `$ACCEPTED` and
/// `$COMPLETED` naming the two answer frames' files.
fn fake_provider(dir: &Path, body: &str) -> PathBuf {
    let hello = frame_file(
        dir,
        "hello.frame",
        &ProviderFrame::Hello(ProviderHello {
            protocol_version: PROTOCOL_VERSION,
            certificate_version: CERTIFICATE_VERSION,
            certificate: measured_certificate(NAME, basis()),
        }),
    );
    let accepted = frame_file(
        dir,
        "accepted.frame",
        &ProviderFrame::Accepted(AssignmentAccepted {
            assignment_id: ASSIGNMENT.to_owned(),
        }),
    );
    let completed = frame_file(
        dir,
        "completed.frame",
        &ProviderFrame::Completed(StageCompleted {
            assignment_id: ASSIGNMENT.to_owned(),
            exit_code: Some(0),
            stdout_bytes: 0,
            stderr_bytes: 0,
            capture_exceeded: false,
        }),
    );
    let script = dir.join("provider.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nACCEPTED={accepted}\nCOMPLETED={completed}\ncat {hello}\n{body}\n",
            accepted = accepted.display(),
            completed = completed.display(),
            hello = hello.display(),
        ),
    )
    .expect("the fake provider is written");
    std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .expect("the fake provider is executable");
    script
}

/// The plan the fake is assigned. The fake reads none of it — these cells are about the
/// assignment's frame budget — so any well-formed `oci` plan serves.
fn plan() -> OciBundlePlan {
    OciBundlePlan {
        config_json: r#"{"ociVersion":"1.0.2"}"#.to_owned(),
        rootfs_mountpoints: Vec::new(),
        container_id: "kata-deadline".to_owned(),
        youki: PinnedRuntime {
            store_path: "/nix/store/0000000000000000000000000000000-youki/bin/youki".to_owned(),
            sha256: "0".repeat(64),
        },
        cgroup_parent: None,
        state_root: "/var/lib/kata/attempts/deadline/oci".to_owned(),
        stdio: OciStdio::Captured,
        egress_hook: None,
    }
}

/// [`plan`] with its `config_json` padded by `filler` bytes, so a cell can size the
/// `Assign` frame. The fake reads none of it.
fn padded_plan(filler: usize) -> OciBundlePlan {
    OciBundlePlan {
        config_json: format!(
            r#"{{"ociVersion":"1.0.2","filler":"{}"}}"#,
            "x".repeat(filler)
        ),
        ..plan()
    }
}

fn spec(binary: PathBuf, stage_timeout: Duration) -> ProviderLaunchSpec {
    let mut spec = ProviderLaunchSpec::production(binary, NAME, Duration::ZERO);
    spec.measured_basis = Some(basis());
    spec.handshake_timeout = Duration::from_secs(30);
    spec.stage_timeout = stage_timeout;
    spec
}

/// **An acceptance and a completion that each arrive inside the budget, but not together,
/// end the assignment at the ONE deadline.** The fake waits for the `Assign` frame, answers
/// `accepted` 1.5 s later and `completed` 3.5 s after that; the budget is four. Each read
/// alone is under it, their sum is not — so the completion read is cut off at the deadline
/// taken before the assignment was written, after the acceptance was decoded, and before
/// twice the budget (what a fresh budget per read would allow).
///
/// **Would red if:** the completion read got a fresh budget of its own (the stage would
/// complete at about five seconds and `run_stage` return `Ok`).
#[tokio::test]
async fn an_acceptance_and_a_completion_share_the_assignments_one_deadline() {
    let dir = tempfile::tempdir().expect("a tempdir");
    let provider = fake_provider(
        dir.path(),
        // The sleeps hold none of the test's stdio: the kill below reaches the shell, not
        // its child, and an orphan holding an inherited pipe is a leak to nextest.
        "head -c 1 > /dev/null\nsleep 1.5 < /dev/null > /dev/null 2>&1\ncat \"$ACCEPTED\"\n\
         sleep 3.5 < /dev/null > /dev/null 2>&1\ncat \"$COMPLETED\"\nexec cat > /dev/null",
    );
    let budget = Duration::from_secs(4);
    let mut supervisor = ProviderSupervisor::launch(&spec(provider, budget))
        .await
        .expect("the fake provider's hello is admitted");
    let began = Instant::now();
    let outcome = supervisor
        .run_stage(
            StageAssignment {
                assignment_id: ASSIGNMENT,
                // v6: the supervisor creates the dir empty; the fake writes nothing
                // to it and the fixture's completed frame reports sizes.
                capture: &kata_provider_protocol::CaptureSpec {
                    spool_dir: dir.path().join("capture").to_string_lossy().into_owned(),
                    limit_bytes: 64 * 1024 * 1024,
                },
            },
            plan(),
        )
        .await;
    let elapsed = began.elapsed();
    let error = outcome.expect_err("the assignment's one deadline ends it before the completion");
    assert!(
        error.to_string().contains("produced no frame before its"),
        "the refusal is the budget's: {error}"
    );
    assert!(
        elapsed >= budget && elapsed < 2 * budget,
        "cut off at the one deadline, {budget:?} after the assignment began: {elapsed:?}"
    );
    let report = supervisor.kill_and_contain(error.to_string()).await;
    assert_eq!(
        report.precondition().frames_read(),
        2,
        "non-vacuity: the acceptance WAS decoded, so the completion read is what was cut off"
    );
}

/// **A provider that never reads its stdin cannot hold the `Assign` write past the
/// deadline.** The assignment carries a plan larger than a pipe's buffer, and the
/// fake never reads, so the write blocks once the pipe is full; it is cut off at the
/// assignment's budget rather than waiting on the provider.
///
/// **Would red if:** the write were unbounded (it would block until the fake exited thirty
/// seconds later, then fail on the closed pipe).
#[tokio::test]
async fn a_provider_that_never_reads_its_assignment_is_cut_off_at_the_deadline() {
    let dir = tempfile::tempdir().expect("a tempdir");
    let provider = fake_provider(dir.path(), "exec sleep 30");
    let budget = Duration::from_secs(2);
    let mut supervisor = ProviderSupervisor::launch(&spec(provider, budget))
        .await
        .expect("the fake provider's hello is admitted");
    let began = Instant::now();
    let error = supervisor
        .assign_stage(
            StageAssignment {
                assignment_id: ASSIGNMENT,
                // v6: the supervisor creates the dir empty; the fake writes nothing
                // to it and the fixture's completed frame reports sizes.
                capture: &kata_provider_protocol::CaptureSpec {
                    spool_dir: dir.path().join("capture").to_string_lossy().into_owned(),
                    limit_bytes: 64 * 1024 * 1024,
                },
            },
            // Well past any pipe buffer, well inside `MAX_FRAME_BYTES`.
            padded_plan(1 << 20),
        )
        .await
        .expect_err("the provider never reads its assignment");
    let elapsed = began.elapsed();
    assert!(
        error.to_string().contains("did not read its assignment"),
        "the refusal is the write's: {error}"
    );
    assert!(
        elapsed >= budget && elapsed < Duration::from_secs(10),
        "cut off at the deadline, not at the provider's exit: {elapsed:?}"
    );
    let _ = supervisor.kill_and_contain(error.to_string()).await;
}

/// **A provider speaking another certificate vocabulary is REFUSED BY NAME at the
/// handshake.** Its hello announces a certificate number this build does not read, and its
/// measured basis carries an axis this build's `deny_unknown_fields` basis cannot decode.
/// The supervisor judges the opening frame's numbers first, so the refusal is
/// `provider_certificate_version_mismatch` — the vocabulary disagreement it is — and never
/// "a frame body was not this protocol version's JSON".
///
/// **Would red if:** the handshake read decoded the whole opening frame before judging its
/// numbers, or judged them differently from `admit`.
#[tokio::test]
async fn a_provider_from_another_certificate_vocabulary_is_refused_by_name_at_the_handshake() {
    let dir = tempfile::tempdir().expect("a tempdir");
    let mut body = serde_json::to_value(ProviderFrame::Hello(ProviderHello {
        protocol_version: PROTOCOL_VERSION,
        certificate_version: CertificateVersion(CERTIFICATE_VERSION.0 + 1),
        certificate: measured_certificate(NAME, basis()),
    }))
    .expect("the hello serializes");
    body["frame"]["certificate"]["measured_basis"]["an_axis_this_build_lacks"] =
        serde_json::Value::Null;
    let json = serde_json::to_vec(&body).expect("the other vocabulary's body serializes");
    let mut framed = u32::try_from(json.len())
        .expect("a small frame")
        .to_be_bytes()
        .to_vec();
    framed.extend_from_slice(&json);
    let hello = dir.path().join("hello.frame");
    std::fs::write(&hello, framed).expect("the frame file is written");
    let script = dir.path().join("provider.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\ncat {hello}\nexec cat > /dev/null\n",
            hello = hello.display()
        ),
    )
    .expect("the fake provider is written");
    std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .expect("the fake provider is executable");

    let error = ProviderSupervisor::launch(&spec(script, Duration::from_secs(5)))
        .await
        .err()
        .expect("another vocabulary's provider must not be admitted");
    let text = error.to_string();
    assert!(
        text.contains("REFUSED at the handshake [provider_certificate_version_mismatch]"),
        "refused by name: {text}"
    );
    assert!(
        !text.contains("an_axis_this_build_lacks"),
        "the refusal is the vocabulary's, not the decoder's: {text}"
    );
}

/// **An assignment too large to frame is refused before a byte of it is written, naming
/// the provider protocol once.** The plan carries more than `MAX_FRAME_BYTES`, so
/// `encode_frame` refuses the `Assign` frame; the supervisor words that refusal through
/// the same `frame_fault` its three read sites use. The fake never reads its stdin, so a
/// refusal that came from the write instead would take the whole budget.
///
/// **Would red if:** the assign-encode site composed `provider protocol:` in front of the
/// `FrameError` again (the codec's `Display` already opens with it).
#[tokio::test]
async fn an_unframeable_assignment_names_the_provider_protocol_once() {
    let dir = tempfile::tempdir().expect("a tempdir");
    let provider = fake_provider(dir.path(), "exec sleep 30");
    let budget = Duration::from_secs(20);
    let mut supervisor = ProviderSupervisor::launch(&spec(provider, budget))
        .await
        .expect("the fake provider's hello is admitted");
    let began = Instant::now();
    let error = supervisor
        .assign_stage(
            StageAssignment {
                assignment_id: ASSIGNMENT,
                capture: &kata_provider_protocol::CaptureSpec {
                    spool_dir: dir.path().join("capture").to_string_lossy().into_owned(),
                    limit_bytes: 64 * 1024 * 1024,
                },
            },
            padded_plan(kata_provider_protocol::MAX_FRAME_BYTES + 1),
        )
        .await
        .expect_err("an assignment above the frame ceiling is not sent")
        .to_string();
    assert!(
        error.contains("byte ceiling; refusing rather than"),
        "the refusal is the frame codec's: {error}"
    );
    assert_eq!(
        error.matches("provider protocol:").count(),
        1,
        "the protocol is named once: {error}"
    );
    assert!(
        began.elapsed() < budget,
        "refused at the encode, not cut off at the write's deadline"
    );
    let _ = supervisor.kill_and_contain(error).await;
}
