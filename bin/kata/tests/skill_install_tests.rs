//! Acceptance: `kata skill install --host claude-code` registers kata as
//! an MCP server and installs a kata skill, then the REGISTERED command really
//! launches `kata mcp` and lists the kata tools (the fresh-host sim).
//!
//! These drive the REAL `kata` binary (`CARGO_BIN_EXE_kata`) as an operator
//! would, then read back the on-disk `.mcp.json` / `SKILL.md` and, for the sim,
//! spawn exactly the command the registration names.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

/// A private, unique scratch project dir (not `TempDir` — this crate's tests
/// stay dependency-light and the dir is best-effort cleaned).
fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "kata-skill-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// Build a command whose host-tool discovery cannot consult the developer's
/// ambient home directory. Installed-main attachment is deliberately excluded:
/// every binary, including this integration-test binary, uses the effective
/// account's fixed owner-home path.
fn isolated_kata_command(program: impl AsRef<std::ffi::OsStr>, root: &Path) -> Command {
    let home = root.join("home");
    let xdg_config = root.join("xdg-config");
    let xdg_data = root.join("xdg-data");
    let xdg_state = root.join("xdg-state");
    let xdg_runtime = root.join("xdg-runtime");
    for dir in [&home, &xdg_config, &xdg_data, &xdg_state, &xdg_runtime] {
        std::fs::create_dir_all(dir).expect("create isolated process directory");
    }

    let mut command = Command::new(program);
    command
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", xdg_config)
        .env("XDG_DATA_HOME", xdg_data)
        .env("XDG_STATE_HOME", xdg_state)
        .env("XDG_RUNTIME_DIR", xdg_runtime);
    command
}

/// Identity of the fixed installed-main descriptor: `None` when absent, else
/// (inode, length, mtime).
///
/// A precondition that the descriptor be ABSENT, before and after the probe,
/// would make the test depend on machine state left by unrelated runs: a
/// `kata serve` that was ever `SIGKILL`ed leaves the file behind, and the test
/// would red on a host where the product was working perfectly.
///
/// Pointing the test at the harness attachment-override environment variable
/// cannot work and is not attempted here, TWICE over.
/// That redirection is the `#[cfg(test)]` definition of
/// `installed_attachment_path`; this test spawns `CARGO_BIN_EXE_kata`, a
/// production binary that compiles the `#[cfg(not(test))]` arm and would ignore
/// the variable. Its sibling's own comment says so: *"Cargo features
/// deliberately cannot enable this lookup"*. And giving production a path
/// override to buy test hygiene would reopen the one-main property, which
/// `attachment.rs` refuses BY DESIGN.
///
/// So the precondition is narrowed instead of redirected. What the "after"
/// check was really guarding is that the registered command never PUBLISHES a
/// descriptor of its own — and the honest spelling of that on a used host is
/// *unchanged*, not *absent*. The inode is part of the identity so a withdraw +
/// republish of byte-identical content is still caught.
fn fixed_attachment_identity(path: &Path) -> Option<(u64, u64, Option<std::time::SystemTime>)> {
    use std::os::unix::fs::MetadataExt as _;
    match std::fs::symlink_metadata(path) {
        Ok(meta) => Some((meta.ino(), meta.len(), meta.modified().ok())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!(
            "cannot inspect fixed installed-main attachment {}: {error}",
            path.display()
        ),
    }
}

/// Run `kata skill install --host claude-code --dir <dir>` and assert success.
fn run_install(dir: &Path) {
    let output = isolated_kata_command(env!("CARGO_BIN_EXE_kata"), dir)
        .args(["skill", "install", "--host", "claude-code", "--dir"])
        .arg(dir)
        .output()
        .expect("run `kata skill install`");
    assert!(
        output.status.success(),
        "`kata skill install` failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn read_mcp_json(dir: &Path) -> Value {
    let text = std::fs::read_to_string(dir.join(".mcp.json")).expect("read .mcp.json");
    serde_json::from_str(&text).expect(".mcp.json is valid JSON")
}

#[test]
fn install_writes_valid_registration_and_skill_file() {
    let dir = scratch_dir("basic");
    run_install(&dir);

    // .mcp.json: a valid registration whose kata entry launches `kata mcp`.
    let mcp = read_mcp_json(&dir);
    let kata = &mcp["mcpServers"]["kata"];
    assert!(
        kata["command"]
            .as_str()
            .is_some_and(|c| c.ends_with("kata")),
        "kata command names the kata binary: {kata}"
    );
    assert_eq!(
        kata["args"][0], "mcp",
        "the entry launches `kata mcp`: {kata}"
    );

    // The skill file exists and teaches the real author→check→run→observe tools.
    let skill =
        std::fs::read_to_string(dir.join(".claude/skills/kata/SKILL.md")).expect("SKILL.md exists");
    for tool in ["author", "check", "run", "observe", "list"] {
        assert!(
            skill.contains(&format!("`{tool}`")),
            "SKILL.md teaches the `{tool}` tool"
        );
    }
    assert!(skill.contains("Starlark"), "SKILL.md is Starlark-only");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn install_merges_a_preexisting_mcp_json_without_clobbering() {
    let dir = scratch_dir("merge");
    // Seed a .mcp.json with an UNRELATED server and an unrelated top-level key.
    let seed = json!({
        "mcpServers": {
            "other": { "command": "other-server", "args": ["serve"] }
        },
        "unrelatedTopLevel": { "keep": true }
    });
    std::fs::write(
        dir.join(".mcp.json"),
        serde_json::to_vec_pretty(&seed).unwrap(),
    )
    .expect("seed .mcp.json");

    run_install(&dir);

    let mcp = read_mcp_json(&dir);
    // Pre-existing server preserved.
    assert_eq!(
        mcp["mcpServers"]["other"]["command"], "other-server",
        "the pre-existing `other` server must not be clobbered: {mcp}"
    );
    // Unrelated top-level key preserved.
    assert_eq!(mcp["unrelatedTopLevel"]["keep"], true);
    // kata added alongside.
    assert_eq!(mcp["mcpServers"]["kata"]["args"][0], "mcp");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn install_is_idempotent() {
    let dir = scratch_dir("idem");
    run_install(&dir);
    let first = read_mcp_json(&dir);
    run_install(&dir);
    let second = read_mcp_json(&dir);

    assert_eq!(
        first, second,
        "second install is a no-op on the registration"
    );
    // Exactly one kata entry, never duplicated.
    assert_eq!(
        second["mcpServers"]
            .as_object()
            .unwrap()
            .keys()
            .filter(|k| *k == "kata")
            .count(),
        1
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The registered command must never invent an embedded main. Whatever the host
/// looks like, `kata mcp` either attaches to THE installed main or fails with a
/// diagnostic an operator can act on — and in every case it leaves the fixed
/// owner descriptor exactly as it found it. The live acceptance test
/// starts a real main and drives two exact MCP registrations against the shared
/// execution identity.
///
/// **It does not require a clean host.** Asserting that the fixed descriptor
/// does not exist, before and after, would fail whenever a `kata serve` had
/// ever been killed, while the product was working correctly. The invariant is
/// asserted against whatever the host actually holds, classified through the
/// PRODUCT's own reader so this test's
/// notion of "discoverable" cannot drift from the child's:
///
/// * descriptor UNREADABLE (absent, malformed, or refused by the owner-only
///   publication policy — `read_installed_attachment` gives all three one
///   diagnostic) → the child must fail and NAME the path plus the recovery
///   command. This is the strongest arm; it is the arm a clean host and every
///   `pgrep-kata`-bookended gate takes.
/// * descriptor READABLE but nothing live behind it (a measured condition: a
///   stale file pointing at `http://127.0.0.1:58393` with no
///   process) → the child must still fail, and name the endpoint it could not
///   reach plus the recovery command. A stale descriptor is NOT authority, and
///   `attachment.rs` says so: *"A stale file after a crash cannot authorize
///   another main"*.
/// * a LIVE main answers the handshake → attaching is the correct behaviour,
///   and the one-main property is carried entirely by the unchanged-descriptor
///   assertion below.
///
/// No arm is satisfied by observing nothing: the first two assert a diagnostic,
/// and all three assert the descriptor identity is untouched.
#[test]
fn registered_command_requires_a_discoverable_installed_main() {
    let dir = scratch_dir("sim");
    let attachment = kata::attachment::installed_attachment_path()
        .expect("resolve fixed effective-owner attachment path");
    let identity_before = fixed_attachment_identity(&attachment);
    let discoverable = kata::attachment::read_installed_attachment();
    run_install(&dir);
    let mcp = read_mcp_json(&dir);
    let kata = &mcp["mcpServers"]["kata"];

    let command = kata["command"]
        .as_str()
        .expect("registered command")
        .to_string();
    let args: Vec<String> = kata["args"]
        .as_array()
        .expect("registered args")
        .iter()
        .map(|a| a.as_str().expect("arg is a string").to_string())
        .collect();

    // Spawn the registration VERBATIM against fixed owner discovery. Nothing
    // redirects the child's descriptor path and nothing can: it is a production
    // binary, so the `#[cfg(test)]` override is not in it. The host's own state
    // is therefore the input, and the assertions below are written against it.
    let output = isolated_kata_command(&command, &dir)
        .args(&args)
        .current_dir(&dir)
        .output()
        .expect("run the registered `kata mcp` command");
    let stderr = String::from_utf8_lossy(&output.stderr);

    match discoverable {
        Err(_) => {
            assert!(
                !output.status.success(),
                "with no readable descriptor there is no main to attach to, and registered \
                 `kata mcp` must not invent an embedded one: {stderr}"
            );
            assert!(
                stderr.contains("installed Kata main is not discoverable")
                    && stderr.contains("kata service status")
                    && stderr.contains(&attachment.display().to_string()),
                "missing-main diagnostic must explain discovery and recovery: {stderr}"
            );
        }
        Ok(descriptor) if !output.status.success() => {
            // A descriptor with nothing live behind it. The child read it, tried
            // the handshake the descriptor's own doc requires, and refused.
            assert!(
                stderr.contains("could not attach to installed main")
                    && stderr.contains(&descriptor.endpoint)
                    && stderr.contains("kata service status"),
                "a stale descriptor is not authority, and the refusal must name the endpoint it \
                 could not reach plus the recovery command: {stderr}"
            );
        }
        Ok(_) => {
            // A live installed main answered. Attaching to it is the correct
            // behaviour and the one-main property is the assertion below.
        }
    }

    let identity_after = fixed_attachment_identity(&attachment);
    assert_eq!(
        identity_after,
        identity_before,
        "the registered `kata mcp` must leave the fixed installed-main descriptor {} exactly as \
         it found it — publishing or replacing one is how a second authority appears",
        attachment.display()
    );

    let _ = std::fs::remove_dir_all(&dir);
}
