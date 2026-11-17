//! Shared helpers for `crates/worker/tests/`.
//!
//! Lives under `tests/common/` (not as a sibling `*.rs`) so cargo treats
//! it as a plain module imported via `mod common;`, not a test target.
//! Put nothing here that has `#[test]` annotations.

#![allow(dead_code)]

/// The adversarial row vocabulary — `ATTACKS`, `Ledger`, `ExecutionDriver` and the
/// per-driver coverage table — shared by every execution driver's binary. See its
/// own header for why it is one module rather than one copy per binary.
pub mod adversarial;

/// Static `x86_64` probes for the syscalls busybox has no applet for — `clone`
/// and `clone3` with `CLONE_NEWUSER`, and an i386-ABI call — written and run
/// inside a container by `busybox printf`.
pub mod static_probe;

use std::process::Command;

/// The protocol version a `kata-provider-*` BINARY announces in its `hello`
/// frame — read off the binary's own stdout, the same bytes the supervisor's
/// handshake decodes. Parsed as a raw JSON shape rather than
/// `kata_provider_protocol`'s current schema ON PURPOSE: a stale binary speaks
/// an older schema, and a probe that could only decode the current one would
/// report "not a frame" where the fact is "announced version 5".
///
/// The child is killed after the hello: providers block on stdin after it, and
/// this probe's only question is the version. Bounded — a binary that never
/// hellos reports that, rather than hanging the cell.
pub fn announced_protocol_version(provider_bin: &std::path::Path) -> Result<u16, String> {
    // `kata-provider-youki` writes its hello only after it has been handed a
    // measured basis to QUOTE — a provider that hellos without one would be
    // certifying an unmeasured container (it refuses that by design, with no
    // frame at all). The probe's basis is a fixture: the certificate content
    // is irrelevant, the hello's version is the only question asked.
    let mut cmd = Command::new(provider_bin);
    if provider_bin
        .file_name()
        .is_some_and(|n| n == "kata-provider-youki")
    {
        let basis = serde_json::json!({
            "youki": {"store_path": "/nix/store/0000000000000000000000000000000f-youki/bin/youki",
                      "sha256": "f".repeat(64)},
            "youki_version": "probe",
            "libseccomp_version": "probe",
            "apparmor_profile_name": "youki",
            "apparmor_profile_sha256": "e".repeat(64),
            "userns_restriction": "restricted",
            "delegated_cgroup_parent": null,
            "functional_probe_id": "kata-stale-provider-probe",
            "residue_denied": false,
        });
        cmd.arg("--measured-basis").arg(basis.to_string());
    }
    let mut child = cmd
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("could not spawn {}: {e}", provider_bin.display()))?;
    let mut stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(kata_provider_protocol::read_frame::<_, serde_json::Value>(
            &mut stdout,
        ));
    });
    let Ok(frame) = rx.recv_timeout(std::time::Duration::from_secs(10)) else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!(
            "{} never wrote a hello frame in 10s",
            provider_bin.display()
        ));
    };
    let _ = child.kill();
    let _ = child.wait();
    let frame = frame.map_err(|e| format!("{}: {e}", provider_bin.display()))?;
    frame
        .get("frame")
        .and_then(|f| f.get("protocol_version"))
        .and_then(serde_json::Value::as_u64)
        .map(|v| u16::try_from(v).unwrap_or(u16::MAX))
        .ok_or_else(|| {
            format!(
                "{}: the hello frame carries no protocol_version: {frame}",
                provider_bin.display()
            )
        })
}

/// `locate_workspace_bin`'s second half for `kata-provider-*` binaries: a
/// LOCATED binary that announces a protocol version other than this build's is
/// a stale artifact sitting in `target/` from an older tree — a RIG defect,
/// never a product verdict. Without this check the cell's first handshake
/// reports `provider_protocol_too_old`, which reads like the PRODUCT refusing
/// where the true defect is the build directory; a gate run once spent its
/// whole red on exactly that misreading. Named `stale_provider_binary` so a
/// ledger can name it apart from the protocol refusal itself.
///
/// Checks only names starting `kata-provider-` — `kata` itself and fixture
/// binaries are not providers.
#[track_caller]
pub fn require_current_provider_protocol(test: &str, name: &str, path: &std::path::Path) {
    if !name.starts_with("kata-provider-") {
        return;
    }
    let announced = announced_protocol_version(path).unwrap_or_else(|e| {
        panic!(
            "{test}: stale_provider_binary probe failed for {path}: {e}",
            path = path.display()
        )
    });
    let current = kata_provider_protocol::PROTOCOL_VERSION.0;
    assert_eq!(
        announced,
        current,
        "{test}: stale_provider_binary at {}: announces v{announced}, this build speaks \
         v{current} — rebuild it (cargo build -p {name})",
        path.display()
    );
}

/// The kata-owned parent cgroup directory for `container`, found by walking this
/// process's own delegated subtree.
///
/// Derived from the KERNEL's view (`/proc/self/cgroup` plus a directory walk) rather
/// than from the plan, because the plan is the subject: a rig that read the path off
/// `OciBundlePlan::cgroup_parent` and then checked that path would be asserting that
/// kata agrees with kata.
pub fn cgroup_leaf(container: &str) -> Option<std::path::PathBuf> {
    let own = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let relative = own.lines().find_map(|line| line.strip_prefix("0::"))?;
    let mut scope = std::path::Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
    // THE SCOPE IS THE PARENT WHEN WE ARE ALREADY INSIDE A KATA LEAF. MEASURED:
    // a `ProviderSupervisor` moves this
    // process into `<scope>/kata.supervisor`, so `/proc/self/cgroup` names that leaf
    // and the container's own cgroup is its SIBLING —
    // `<scope>/kata.provider.youki.<pid>/kata.oci.<id>`. Walking from the leaf finds
    // nothing and the "the directory existed" baseline reds with the container still
    // answering on its stdout.
    if scope
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("kata."))
        && let Some(parent) = scope.parent()
    {
        scope = parent.to_path_buf();
    }
    // The provider's own sweep root is one level in; kata's parent for this container
    // is named after it beneath that. Walk rather than compose, so the name this
    // function looks for is the container id and nothing else.
    fn walk(dir: &std::path::Path, needle: &str, depth: usize) -> Option<std::path::PathBuf> {
        if depth == 0 {
            return None;
        }
        for entry in std::fs::read_dir(dir).ok()?.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(needle))
            {
                return Some(path);
            }
            if let Some(found) = walk(&path, needle, depth - 1) {
                return Some(found);
            }
        }
        None
    }
    walk(&scope, container, 4)
}
