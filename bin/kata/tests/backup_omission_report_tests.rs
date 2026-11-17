//! REGRESSION — `kata backup` tells the operator WHY an authoritative asset is
//! missing from the artifact it just wrote, through the REAL binary's stdout.
//!
//! # The bad state, and why it could not be seen from inside the process
//!
//! A tree-bound overrun DEGRADES instead of failing the whole backup, and that
//! is justified entirely on the operator being TOLD. A reason string that
//! reached only a `tracing::warn!` inside `capture_tree`'s omission arm would be
//! formatted and dropped: `run_backup_cmd` installs no subscriber
//! (`grep -rn init_telemetry bin/kata/src` hits `solo.rs` and `mcp.rs`, and
//! nothing else), so the event goes to the no-op global dispatcher. The
//! operator would learn `cas` was missing and never learn why, and a missing
//! authoritative asset an operator cannot explain is indistinguishable from a
//! bug in the backup.
//!
//! That is why this test spawns the SHIPPED BINARY and reads its stdout rather
//! than asserting on a `CompletenessVerdict`: the defect is invisible at every
//! layer above the process boundary. A struct-level assertion would pass
//! against the defect.
//!
//! # The fixture overruns a PRODUCTION bound — no test seam is involved
//!
//! `kata backup` runs at `TreeBounds::PRODUCTION`, so a fixture that reached the
//! degradation through a lowered bound would be proving something about a seam.
//! The per-member bound is the one production bound a test can overrun for free:
//! a SPARSE file one byte past `MAX_TREE_FILE_BYTES` is rejected on its
//! `symlink_metadata` length before a single byte is read or copied, so the
//! fixture costs 0 disk blocks (measured: `st_blocks` = 0) and the capture never
//! touches it.
//!
//! The size is DERIVED from the exported bound rather than typed. A literal
//! would be a hang waiting to happen: raise `MAX_TREE_FILE_BYTES` above the
//! literal and the capture would start actually copying and hashing a terabyte
//! of zeros instead of failing.
//!
//! # The fixture also carries REAL objects
//!
//! `TreeCapture::omitted_after_writing`'s `remove_dir_all` is what keeps a
//! degraded artifact from carrying a prefix of an authoritative tree its
//! manifest does not claim, and the other assertions about it run through
//! `backup_data_dir_with_tree_bounds` — a `#[cfg(test)]` seam — at bounds around
//! 100 KB. This is the ONE test at production bounds; a fixture planting only
//! the oversized member would have `trees/cas` created and removed having
//! published NOTHING, leaving the production-bounds removal with no prefix to
//! remove.
//!
//! Three real `CasStore::put` objects sit beside it. Every CAS shard sorts
//! before `ff` and no 64-hex name sorts above 64 `f`s, so `walk_tree_entries` —
//! which sorts children at every level — copies, digests, address-verifies and
//! RENAMES all three into the artifact before it ever stats the overrun member.
//! The artifact genuinely holds a prefix of `cas` at the moment the removal
//! runs, which is the state `trees/` is asserted empty against, and the
//! counterfactual at the bottom shows the same three members landing at the same
//! production bounds when the overrun member is gone.

use std::path::Path;
use std::process::Command;

use kata_core::store::backup::{MAX_TREE_FILE_BYTES, TREES_SUBDIR};
use kata_core::store::cas::{CasStore, INLINE_THRESHOLD};

/// The shipped binary.
fn kata() -> Command {
    Command::new(env!("CARGO_BIN_EXE_kata"))
}

/// A minimal installed-main config selecting `data`, with no `[agents]` rows:
/// `kata backup` runs no stage, so it resolves no agent.
fn write_config(config: &std::path::Path, data: &std::path::Path) {
    std::fs::write(
        config,
        format!(
            r#"[node]
id = "backup-omission-report"
data_dir = "{}"

[runtime]
max_concurrent_dispatches = 64

[workers]
dispatch_deadline_ms = 30000
assignment_start_deadline_ms = 900000
heartbeat_interval_ms = 10000
heartbeat_grace_ms = 30000
max_workers = 4
transports = [{{ type = "supervised_node" }}]

[api]
bind = "127.0.0.1:0"

[api.auth]
type = "disabled"

[agents]
"#,
            data.display()
        ),
    )
    .unwrap();
}

/// Every path under an artifact's `trees/`, files AND directories, sorted.
///
/// Directories are included because an empty `trees/cas/ab/` left behind is both
/// bytes an operator pays to store that no manifest names and the evidence that
/// the removal was partial rather than complete.
fn tree_listing(artifact: &Path) -> Vec<String> {
    fn walk(root: &Path, prefix: &str, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(root) else {
            return;
        };
        for entry in entries {
            let entry = entry.expect("read a tree entry");
            let name = entry.file_name().to_string_lossy().into_owned();
            let relative = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            out.push(relative.clone());
            if entry.file_type().expect("stat a tree entry").is_dir() {
                walk(&entry.path(), &relative, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(&artifact.join(TREES_SUBDIR), "", &mut out);
    out.sort();
    out
}

/// The omitted-asset list, sliced out of a rendered report.
///
/// Slicing rather than searching the whole report: the capture-order section
/// renders `  operational.db [NucleusLast]` in the same `name [bracket]` shape,
/// so a whole-report search cannot tell "reported omitted" from "reported
/// captured, in rank order".
fn omitted_section(report: &str) -> &str {
    report
        .split_once("authoritative assets NOT captured =")
        .expect("the completeness block must be present")
        .1
        .split_once("authoritative assets satisfied by external rebind")
        .expect("the omission list ends at the rebind list")
        .0
}

#[test]
fn kata_backup_names_the_omitted_tree_and_the_bound_that_omitted_it() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    // A real database, so this run also shows the DEGRADATION: the artifact the
    // operator gets still holds every database that was capturable.
    drop(kata_core::OperationalDb::open(data.join("operational.db")).unwrap());

    // THREE REAL OBJECTS, through `CasStore::put` rather than hand-written
    // files: a file under `cas/` whose bytes do not hash to its path is not a
    // CAS object, and `verify_member_address` would refuse the capture outright
    // instead of letting it reach the bound.
    {
        let cas = CasStore::open(data.join("cas.db"), data.join("cas")).unwrap();
        for seed in 0..3_u8 {
            cas.put(&vec![0xC0 ^ seed; INLINE_THRESHOLD + 1 + usize::from(seed)])
                .unwrap();
        }
        cas.checkpoint().unwrap();
    }

    // The overrun member: sparse, one byte past the production per-member bound,
    // named the way a CAS object is named so nothing else in the walk skips it,
    // and placed at the position that sorts LAST — `ff` is the last shard a CAS
    // layout can hold and 64 `f`s is the largest 64-hex name inside it — so
    // every real object above is already published when the bound trips.
    let member = "ff/".to_string() + &"f".repeat(64);
    std::fs::create_dir_all(data.join("cas").join("ff")).unwrap();
    let oversized = MAX_TREE_FILE_BYTES + 1;
    let file = std::fs::File::create(data.join("cas").join(&member)).unwrap();
    file.set_len(oversized).unwrap();
    drop(file);
    assert_eq!(
        std::fs::metadata(data.join("cas").join(&member))
            .unwrap()
            .len(),
        oversized,
        "the fixture must actually be over the bound, or the capture will succeed and this test \
         proves nothing"
    );

    let config = dir.path().join("kata.toml");
    write_config(&config, &data);
    let out = dir.path().join("artifact");

    let run = kata()
        .args([
            "backup",
            "--config",
            config.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .expect("spawn kata backup");
    let stdout = String::from_utf8_lossy(&run.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&run.stderr).into_owned();
    assert!(
        run.status.success(),
        "an oversized tree member is a CAPACITY fact; `kata backup` must still write the artifact \
         for the databases that were perfectly capturable.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // The degradation happened at all: the databases landed and no tree is
    // claimed. Without this the assertions below could be measuring a report
    // about an artifact that captured everything.
    assert!(
        stdout.contains("\n  operational.db\n"),
        "the databases must still be captured:\n{stdout}"
    );
    let omitted = omitted_section(&stdout);
    assert!(
        omitted
            .lines()
            .any(|line| line.trim().starts_with("cas [MainDataDir]")),
        "the report must NAME the omitted tree with the root a recovery has to resolve:\n{stdout}"
    );

    // THE FIX — and the whole point. The reason is on the operator's screen,
    // attached to the asset it explains, on the path an operator actually runs.
    let explained: Vec<&str> = omitted
        .lines()
        .skip_while(|line| !line.trim().starts_with("cas [MainDataDir]"))
        .skip(1)
        .take(1)
        .collect();
    assert!(
        explained
            .first()
            .is_some_and(|line| line.contains("omitted by this capture:")),
        "the omission's REASON must be printed under the asset it explains; the operator was told \
         `cas` is missing and not told why, which is indistinguishable from a bug in the \
         backup:\n{stdout}"
    );
    let reason = explained[0];
    assert!(
        reason.contains("over the bounded per-member maximum")
            && reason.contains(&oversized.to_string())
            && reason.contains(&MAX_TREE_FILE_BYTES.to_string()),
        "the reason must name the bound, the measurement, and the limit — an operator who cannot \
         tell 'too big' from 'too many' cannot act on either:\n{reason}"
    );

    // THE REMOVAL, at PRODUCTION bounds. Every other assertion about
    // `TreeCapture::omitted_after_writing` runs through the `#[cfg(test)]` bounds
    // seam; this one runs through the binary an operator invokes, over a tree
    // that really did have three members published into the artifact before the
    // last one overran. `trees/` must come out exactly as empty as it went in,
    // shard directories included: a populated `trees/cas/` beside a manifest
    // claiming no tree leaves a later reader to guess which is lying.
    assert_eq!(
        tree_listing(&out),
        Vec::<String>::new(),
        "the degraded artifact must carry no prefix of the tree its manifest does not claim"
    );

    // NON-VACUOUS in the other direction: the same binary over the same data
    // directory WITHOUT the oversized member captures the tree and prints no
    // omission reason for it, so the block above is bought by the bound.
    std::fs::remove_file(data.join("cas").join(&member)).unwrap();
    let clean_out = dir.path().join("artifact-clean");
    let clean = kata()
        .args([
            "backup",
            "--config",
            config.to_str().unwrap(),
            "--out",
            clean_out.to_str().unwrap(),
        ])
        .output()
        .expect("spawn kata backup");
    assert!(clean.status.success());
    let clean_stdout = String::from_utf8_lossy(&clean.stdout).into_owned();
    assert!(
        !omitted_section(&clean_stdout)
            .lines()
            .any(|line| line.trim().starts_with("cas [MainDataDir]")),
        "with the oversized member gone the tree is captured, so `cas` must leave the omitted \
         list:\n{clean_stdout}"
    );
    assert!(
        !clean_stdout.contains("omitted by this capture:"),
        "and no asset in this artifact carries an omission reason, or the reason line is being \
         printed unconditionally:\n{clean_stdout}"
    );
    // And it is what makes the removal assertion above non-vacuous: the same
    // three members land at the SAME production bounds, so the degraded run
    // above had them published in `trees/cas/` and really did remove them,
    // rather than removing a directory that was never populated — which is
    // exactly what this test did before it planted any real object.
    let landed: Vec<String> = tree_listing(&clean_out)
        .into_iter()
        .filter(|path| path.matches('/').count() == 2)
        .collect();
    assert_eq!(
        landed.len(),
        3,
        "the counterfactual must land all three members, or it cannot vouch for what the degraded \
         run had to remove: {landed:?}"
    );
}
