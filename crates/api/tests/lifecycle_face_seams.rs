//! The operational nucleus's face-level properties: the lifecycle face's
//! fixture seams stay out of production, and the two-sequence-spaces guard
//! keeps SSE delivery ordering off `transitions.seq`.

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("api crate lives under <repo>/crates/api")
        .to_path_buf()
}

/// Every PRODUCTION Rust source, with `#[cfg(test)]`-gated regions blanked.
///
/// "Production" means "no non-`cfg(test)` callers", so
/// this corpus must exclude test code by CONSTRUCTION, not by path convention.
/// A path-only filter is not enough on either axis:
///
/// * `crates/<crate>/src/<mod>/tests.rs` is reached only through
///   `#[cfg(test)] mod tests;`, yet nothing in its path says `/tests/` or
///   `_tests.rs`. It is test code whose path looks like production.
/// * an inline `#[cfg(test)] mod tests { .. }` block lives inside a file that IS
///   production. Path filtering cannot see it at all.
///
/// Admitting either one lets a sanctioned exception be granted to something that
/// is not production code — e.g. a file sanctioned on the strength of two
/// lines inside its `#[cfg(test)] mod tests`.
fn runtime_sources() -> Vec<(PathBuf, String)> {
    let mut paths = Vec::new();
    collect(&repo_root().join("crates"), &mut paths);
    collect(&repo_root().join("bin"), &mut paths);
    paths.retain(|path| is_runtime(path));
    paths.sort();
    paths
        .into_iter()
        .filter_map(|path| {
            let text = fs::read_to_string(&path).ok()?;
            let stripped = strip_test_regions(&text);
            Some((path, stripped))
        })
        .collect()
}

fn is_runtime(path: &Path) -> bool {
    let text = path.to_string_lossy().replace('\\', "/");
    if !text.contains("/src/") || text.contains("/tests/") {
        return false;
    }
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    name != "tests.rs" && !name.ends_with("_tests.rs")
}

/// Blank every `#[cfg(..)]`-gated item whose predicate mentions `test`, keeping
/// every byte's LINE preserved so findings still report the true line number.
///
/// Limitation: brace matching does not skip braces inside string literals.
fn strip_test_regions(text: &str) -> String {
    let mut buf = text.as_bytes().to_vec();
    let mut cursor = 0usize;
    while let Some((hash, open_paren)) = find_cfg_attribute(&buf, cursor) {
        let Some(close_paren) = match_delimiters(&buf, open_paren, b'(', b')') else {
            break;
        };
        let Some(attribute_end) = position_of(&buf, close_paren, b']') else {
            break;
        };
        if !predicate_mentions_test(&buf[open_paren..=close_paren]) {
            cursor = hash + 1;
            continue;
        }
        let end = item_end(&buf, attribute_end + 1);
        for byte in &mut buf[hash..end] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
        cursor = hash;
    }
    String::from_utf8(buf).unwrap_or_else(|_| text.to_string())
}

/// Locate the next `#[cfg(`, tolerating whitespace between every token.
/// Returns `(index of '#', index of the opening paren)`.
fn find_cfg_attribute(buf: &[u8], from: usize) -> Option<(usize, usize)> {
    let skip_spaces = |mut at: usize| {
        while at < buf.len() && buf[at].is_ascii_whitespace() {
            at += 1;
        }
        at
    };
    for hash in from..buf.len() {
        if buf[hash] != b'#' {
            continue;
        }
        let at = skip_spaces(hash + 1);
        if buf.get(at) != Some(&b'[') {
            continue;
        }
        let at = skip_spaces(at + 1);
        if !buf[at..].starts_with(b"cfg") {
            continue;
        }
        let at = skip_spaces(at + 3);
        if buf.get(at) == Some(&b'(') {
            return Some((hash, at));
        }
    }
    None
}

fn match_delimiters(buf: &[u8], open: usize, opener: u8, closer: u8) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, byte) in buf[open..].iter().enumerate() {
        if *byte == opener {
            depth += 1;
        } else if *byte == closer {
            depth -= 1;
            if depth == 0 {
                return Some(open + offset);
            }
        }
    }
    None
}

fn position_of(buf: &[u8], from: usize, needle: u8) -> Option<usize> {
    buf[from..]
        .iter()
        .position(|b| *b == needle)
        .map(|at| from + at)
}

/// `#[cfg(test)]`, `#[cfg(any(test, ..))]`, `#[cfg(feature = "test-support")]`.
fn predicate_mentions_test(predicate: &[u8]) -> bool {
    let text = String::from_utf8_lossy(predicate);
    if text.contains("test-support") || text.contains("test_support") {
        return true;
    }
    // Whole-word `test`, so `latest` / `contest` do not gate a production item.
    let word = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    let bytes = text.as_bytes();
    bytes.windows(4).enumerate().any(|(at, window)| {
        window == b"test"
            && !bytes
                .get(at.wrapping_sub(1))
                .is_some_and(|b| at > 0 && word(*b))
            && !bytes.get(at + 4).is_some_and(|b| word(*b))
    })
}

/// The end of the item an attribute applies to: past its `{..}` block, or past
/// the `;` of an item like `#[cfg(test)] mod tests;` that has no block.
fn item_end(buf: &[u8], from: usize) -> usize {
    let brace = position_of(buf, from, b'{');
    let semicolon = position_of(buf, from, b';');
    match (brace, semicolon) {
        (Some(brace), Some(semicolon)) if semicolon < brace => semicolon + 1,
        (Some(brace), _) => {
            match_delimiters(buf, brace, b'{', b'}').map_or(buf.len(), |end| end + 1)
        }
        (None, Some(semicolon)) => semicolon + 1,
        (None, None) => buf.len(),
    }
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            collect(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// The operational-backed face that defines the lifecycle's fixture seams.
const OPERATIONAL_LIFECYCLE_FACE: &str = "crates/workflow/src/execution_lifecycle.rs";

/// Every fixture seam on [`OPERATIONAL_LIFECYCLE_FACE`]: each `fn` the face
/// defines behind the `test-support` feature, and each
/// `debug_*` `OperationalDb` accessor those gated bodies call.
///
/// The seams are fixture writers of the program/lifecycle nucleus (raw program
/// bytes, a lifecycle with no invocation envelope, a combined admit+authorize, a
/// one-call terminal, a row delete) and fault injectors (rejected writes, a
/// dropped lifecycle table). None is a production path: admission and
/// terminalization are. The list is EXACT, not a sample:
/// [`test_support_seams_match_the_face_exactly`] derives the same set from the
/// face, so a new seam that is not listed fails, and so does a listed seam that
/// lost its `cfg` gate (it stops being derived) or was deleted.
const TEST_SUPPORT_SEAMS: &[&str] = &[
    "debug_delete_execution",
    "debug_drop_lifecycle_table",
    "debug_put_raw_program",
    "debug_reject_lifecycle_updates",
    "debug_reject_program_inserts",
    "delete",
    "drop_lifecycle_table_for_test",
    "mark_terminal",
    "put_current_program",
    "put_current_program_with_target",
    "put_raw_active_program_json",
    "put_raw_legacy_evidence_json",
    "reject_lifecycle_writes_for_test",
    "reject_program_writes_for_test",
];

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// The identifier that starts at `at`, if any.
fn identifier_at(text: &str, at: usize) -> Option<&str> {
    let length = text.as_bytes()[at..]
        .iter()
        .take_while(|byte| is_identifier_byte(**byte))
        .count();
    (length > 0).then(|| &text[at..at + length])
}

/// The seams derived from the face itself: the name after every `fn ` and every
/// `.debug_` call inside an item gated on the `test-support` feature. A plain
/// `#[cfg(test)]` item (the face's own unit tests) is not a seam: no other crate
/// can reach it.
fn derived_face_seams(raw: &str) -> Vec<String> {
    let buf = raw.as_bytes();
    let mut gated = String::new();
    let mut cursor = 0usize;
    while let Some((hash, open_paren)) = find_cfg_attribute(buf, cursor) {
        cursor = hash + 1;
        let Some(close_paren) = match_delimiters(buf, open_paren, b'(', b')') else {
            break;
        };
        if !String::from_utf8_lossy(&buf[open_paren..=close_paren]).contains("test-support") {
            continue;
        }
        let Some(attribute_end) = position_of(buf, close_paren, b']') else {
            break;
        };
        gated.push_str(&raw[attribute_end + 1..item_end(buf, attribute_end + 1)]);
        gated.push('\n');
    }
    let mut seams = Vec::new();
    for (marker, prefix) in [("fn ", ""), (".debug_", "debug_")] {
        let mut from = 0;
        while let Some(found) = gated[from..].find(marker) {
            let at = from + found;
            from = at + marker.len();
            if marker == "fn " && at > 0 && is_identifier_byte(gated.as_bytes()[at - 1]) {
                continue;
            }
            if let Some(name) = identifier_at(&gated, from) {
                seams.push(format!("{prefix}{name}"));
            }
        }
    }
    seams.sort();
    seams.dedup();
    seams
}

/// A method or path reference to `seam` on `line` (`.seam` or `::seam`, as a
/// whole identifier). A bare `seam` is a local name, not a call into the face.
fn references_seam(line: &str, seam: &str) -> bool {
    let bytes = line.as_bytes();
    line.match_indices(seam).any(|(at, _)| {
        let end = at + seam.len();
        let qualified = at > 0 && matches!(bytes[at - 1], b'.' | b':');
        qualified && !bytes.get(end).is_some_and(|byte| is_identifier_byte(*byte))
    })
}

#[test]
fn test_support_seams_match_the_face_exactly() {
    let face_path = repo_root().join(OPERATIONAL_LIFECYCLE_FACE);
    let raw = fs::read_to_string(&face_path).expect("read the operational-backed lifecycle face");
    let derived = derived_face_seams(&raw);
    let mut listed: Vec<String> = TEST_SUPPORT_SEAMS
        .iter()
        .copied()
        .map(String::from)
        .collect();
    listed.sort();
    assert_eq!(
        derived, listed,
        "TEST_SUPPORT_SEAMS must name exactly the test-gated fns of \
         {OPERATIONAL_LIFECYCLE_FACE} and the `debug_*` accessors they call; a seam missing \
         from the derived set is deleted or no longer test-gated (a fixture writer reachable \
         from production), a seam missing from the list is unguarded"
    );
}

#[test]
fn references_seam_matches_qualified_whole_identifiers_only() {
    assert!(references_seam("face.delete(id)", "delete"));
    assert!(references_seam("    .mark_terminal(", "mark_terminal"));
    assert!(references_seam(
        "Face::put_current_program(f, id)",
        "put_current_program"
    ));
    assert!(!references_seam("face.delete_all(id)", "delete"));
    assert!(!references_seam("face.undelete(id)", "delete"));
    assert!(!references_seam("let delete = true;", "delete"));
}

#[test]
fn no_runtime_source_references_a_test_support_seam() {
    let root = repo_root();
    let mut findings = Vec::new();
    for (path, source) in runtime_sources() {
        let relative = relative(&root, &path);
        for (index, line) in source.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") {
                continue;
            }
            for seam in TEST_SUPPORT_SEAMS {
                if references_seam(trimmed, seam) {
                    findings.push(format!("{relative}:{}: {trimmed}", index + 1));
                }
            }
        }
    }
    assert!(
        findings.is_empty(),
        "the lifecycle face's fixture seams must have ZERO runtime references; found:\n{}",
        findings.join("\n")
    );
}

/// The two-sequence-spaces invariant: `transitions.seq` is AUTHORITY ordering and
/// `ledger_events.sequence` is DELIVERY ordering. They are two sequence spaces
/// with one authority, and a reader that compares them is wrong even though the
/// comparison type-checks (both are integers).
///
/// # The POSITIVE half lives on a live plane
///
/// A TEXT match such as `assert!(events.contains("event_head()"))` cannot tell a
/// live plane from a corpse: it stays GREEN while the stream is dead. So the
/// positive statement lives in
/// `events_stream::the_sse_since_bound_admits_delivery_sequences_and_refuses_authority_ones`,
/// which drives a real run and asserts that an AUTHORITY sequence above the
/// delivery head is REFUSED while the highest sequence the client actually
/// received is ACCEPTED — and which fails outright when no frame is delivered.
///
/// What stays here is the half a behavioural test structurally cannot cover: an
/// ANTI-PATTERN scan for any reader that RELATES the two spaces. A negative over
/// all runtime source has no live instance to observe by construction, which is
/// exactly when a source scan is the right instrument.
#[test]
fn no_reader_relates_the_delivery_sequence_to_the_authority_sequence() {
    let root = repo_root();
    let events =
        fs::read_to_string(root.join("crates/api/src/rest/events.rs")).expect("read the SSE route");
    assert!(
        !events.contains("transition_seq")
            && !events.contains("transitions.seq")
            && !events.contains("applied_through_seq"),
        "the SSE delivery plane must never consult the operational transition sequence: \
         `ledger_events.sequence` stays delivery ordering (delivery/read planes stay \
         rebuildable)"
    );

    let mut findings = Vec::new();
    for (path, source) in runtime_sources() {
        let relative = relative(&root, &path);
        if relative.starts_with("crates/core/src/operational/") {
            continue;
        }
        for (index, line) in source.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") {
                continue;
            }
            let names_delivery = trimmed.contains("event_head") || trimmed.contains("since");
            let names_authority =
                trimmed.contains("transition_seq") || trimmed.contains("applied_through_seq");
            if names_delivery && names_authority {
                findings.push(format!("{relative}:{}: {trimmed}", index + 1));
            }
        }
    }
    assert!(
        findings.is_empty(),
        "no reader may relate the delivery sequence to the authority sequence; found:\n{}",
        findings.join("\n")
    );
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}
