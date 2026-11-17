//! The bounded git-format text diff between two recorded commits — the
//! `{{ target.diff }}` answer.
//!
//! Both ends are commits in the repository store, so the text is a function of
//! the two ids: no working copy, no workspace file and no ref is read, and the
//! same two commits render the same text. The format is git's unified diff with
//! three lines of context (`diff --git`, the mode and `index` lines, `---`/`+++`,
//! `@@` hunks, `\ No newline at end of file`, `Binary files … differ`). A path is
//! written as git writes it under its default `core.quotePath=true`
//! ([`git_name`]): C-quoted when a byte needs it, so no path — the PR author's
//! choice — can open a line git would not write. Two stated differences: a line
//! that is not UTF-8 is written lossily (U+FFFD for each invalid sequence), and
//! a path whose NAME is not UTF-8 is never written at all — jj-lib refuses to
//! read a tree holding one, so when a directory that differs between the two
//! commits (the root does whenever anything changed) holds one, the diff fails
//! instead of rendering.
//! Hunk boundaries follow jj's line diff, which can split a change differently
//! from git's default algorithm on the same pair of files.
//!
//! The text is cut at a whole line once the next line would pass the caller's
//! byte bound, and no later file is read. Paths and contents are what the
//! commits' authors wrote: the text is untrusted.

use std::fmt::Write as _;

use futures::StreamExt as _;
use gix::bstr::BStr;
use jj_lib::conflict_labels::ConflictLabels;
use jj_lib::conflicts::{ConflictMarkerStyle, ConflictMaterializeOptions, materialize_tree_value};
use jj_lib::diff_presentation::LineCompareMode;
use jj_lib::diff_presentation::unified::{
    DiffLineType, GitDiffPart, git_diff_part, unified_diff_hunks,
};
use jj_lib::files::FileMergeHunkLevel;
use jj_lib::matchers::EverythingMatcher;
use jj_lib::merge::{Diff, SameChange};
use jj_lib::merged_tree::TreeDiffEntry;
use jj_lib::tree_merge::MergeOptions;
use kata_types::{KataError, KataResult};

use kata_effects_contract::RecordedTextDiff;

use super::JjBackend;

/// Lines of unchanged context around each hunk — git's default.
const CONTEXT_LINES: usize = 3;

impl JjBackend {
    /// [`crate::ExecutionWorkspaceProvider::recorded_commit_text_diff`].
    pub(super) fn recorded_commit_text_diff(
        &self,
        base_commit: &str,
        head_commit: &str,
        max_bytes: usize,
    ) -> KataResult<RecordedTextDiff> {
        let (store, base, head) = self.recorded_commit_trees(base_commit, head_commit)?;
        let what = format!("{base_commit}..{head_commit}");
        let options = ConflictMaterializeOptions {
            marker_style: ConflictMarkerStyle::Git,
            marker_len: None,
            merge: MergeOptions {
                hunk_level: FileMergeHunkLevel::Line,
                same_change: SameChange::Accept,
            },
        };
        let labels = ConflictLabels::unlabeled();
        let mut out = BoundedText::new(max_bytes);
        let matcher = EverythingMatcher;
        let mut stream = base.diff_stream(&head, &matcher);
        while let Some(TreeDiffEntry { path, values }) = Self::block_on(stream.next()) {
            let values = values
                .map_err(|err| KataError::Internal(format!("failed to diff {what}: {err}")))?;
            let part = |value| -> KataResult<GitDiffPart> {
                let materialized = Self::block_on(materialize_tree_value(
                    &store, &path, value, &labels,
                ))
                .map_err(|err| {
                    KataError::Internal(format!(
                        "failed to read {} in {what}: {err}",
                        path.as_internal_file_string()
                    ))
                })?;
                git_diff_part(&path, materialized, &options).map_err(|err| {
                    KataError::Internal(format!(
                        "failed to read {} in {what}: {err}",
                        path.as_internal_file_string()
                    ))
                })
            };
            let parts = Diff::new(part(values.before)?, part(values.after)?);
            if !write_file_diff(&mut out, path.as_internal_file_string(), &parts) {
                break;
            }
        }
        Ok(out.finish())
    }
}

/// Text that refuses a line once it would pass `max` bytes, and every line
/// after that one.
struct BoundedText {
    text: String,
    max: usize,
    truncated: bool,
}

impl BoundedText {
    const fn new(max: usize) -> Self {
        Self {
            text: String::new(),
            max,
            truncated: false,
        }
    }

    /// Append `line` and a newline, or mark the text truncated. `false` once
    /// the text is truncated.
    fn line(&mut self, line: &str) -> bool {
        if self.truncated || self.text.len() + line.len() + 1 > self.max {
            self.truncated = true;
            return false;
        }
        self.text.push_str(line);
        self.text.push('\n');
        true
    }

    fn finish(self) -> RecordedTextDiff {
        RecordedTextDiff {
            text: self.text,
            truncated: self.truncated,
        }
    }
}

/// One path's section of the diff. `false` once the text is truncated.
fn write_file_diff(out: &mut BoundedText, path: &str, parts: &Diff<GitDiffPart>) -> bool {
    let (before, after) = (&parts.before, &parts.after);
    let (old_name, new_name) = (git_name("a/", path), git_name("b/", path));
    let mut header = vec![format!("diff --git {old_name} {new_name}")];
    let index = format!("index {}..{}", before.hash, after.hash);
    match (before.mode, after.mode) {
        (None, Some(mode)) => {
            header.push(format!("new file mode {mode}"));
            header.push(index);
        }
        (Some(mode), None) => {
            header.push(format!("deleted file mode {mode}"));
            header.push(index);
        }
        (Some(old), Some(new)) if old != new => {
            header.push(format!("old mode {old}"));
            header.push(format!("new mode {new}"));
            if before.hash != after.hash {
                header.push(index);
            }
        }
        (Some(mode), Some(_)) => {
            if before.hash != after.hash {
                header.push(format!("{index} {mode}"));
            }
        }
        // The stream yields only paths present on at least one side.
        (None, None) => {}
    }
    for line in &header {
        if !out.line(line) {
            return false;
        }
    }
    if before.content.contents == after.content.contents {
        return true;
    }
    let label = |part: &GitDiffPart, name: String| match part.mode {
        None => "/dev/null".to_owned(),
        Some(_) => name,
    };
    let (left, right) = (label(before, old_name), label(after, new_name));
    if before.content.is_binary || after.content.is_binary {
        return out.line(&format!("Binary files {left} and {right} differ"));
    }
    if !out.line(&file_label_line("---", &left)) || !out.line(&file_label_line("+++", &right)) {
        return false;
    }
    let contents = Diff::new(
        BStr::new(before.content.contents.as_slice()),
        BStr::new(after.content.contents.as_slice()),
    );
    for hunk in unified_diff_hunks(contents, CONTEXT_LINES, LineCompareMode::Exact) {
        let header = format!(
            "@@ -{} +{} @@",
            hunk_range(&hunk.left_line_range),
            hunk_range(&hunk.right_line_range)
        );
        if !out.line(&header) {
            return false;
        }
        for (kind, tokens) in &hunk.lines {
            let prefix = match kind {
                DiffLineType::Context => ' ',
                DiffLineType::Removed => '-',
                DiffLineType::Added => '+',
            };
            let bytes: Vec<u8> = tokens
                .iter()
                .flat_map(|(_, part)| part.iter())
                .copied()
                .collect();
            let (body, terminated) = match bytes.strip_suffix(b"\n") {
                Some(body) => (body, true),
                None => (bytes.as_slice(), false),
            };
            if !out.line(&format!("{prefix}{}", String::from_utf8_lossy(body))) {
                return false;
            }
            if !terminated && !out.line("\\ No newline at end of file") {
                return false;
            }
        }
    }
    true
}

/// `prefix` and `path` as one name the way git writes it in a diff header
/// (`quote_two` over `quote_c_style`, `core.quotePath=true`): verbatim unless
/// a byte needs quoting ([`needs_c_quote`]); otherwise wrapped in double
/// quotes, the prefix inside them, with `\a \b \t \n \v \f \r \" \\`
/// escapes and three-digit octal for every other byte that needs quoting —
/// each byte of a multi-byte character on its own.
fn git_name(prefix: &str, path: &str) -> String {
    let name = format!("{prefix}{path}");
    if !name.bytes().any(needs_c_quote) {
        return name;
    }
    let mut quoted = String::with_capacity(name.len() + 2);
    quoted.push('"');
    for byte in name.bytes() {
        match byte {
            0x07 => quoted.push_str("\\a"),
            0x08 => quoted.push_str("\\b"),
            b'\t' => quoted.push_str("\\t"),
            b'\n' => quoted.push_str("\\n"),
            0x0b => quoted.push_str("\\v"),
            0x0c => quoted.push_str("\\f"),
            b'\r' => quoted.push_str("\\r"),
            b'"' => quoted.push_str("\\\""),
            b'\\' => quoted.push_str("\\\\"),
            byte if needs_c_quote(byte) => {
                let _ = write!(quoted, "\\{byte:03o}");
            }
            byte => quoted.push(char::from(byte)),
        }
    }
    quoted.push('"');
    quoted
}

/// Whether git's `quote_c_style` quotes a name holding `byte` under
/// `core.quotePath=true`: a C0 control byte, `"`, `\`, DEL, or any byte of a
/// non-ASCII character.
const fn needs_c_quote(byte: u8) -> bool {
    byte < 0x20 || byte == b'"' || byte == b'\\' || byte >= 0x7f
}

/// A `---` / `+++` line as git writes it: a label holding a space is followed
/// by a tab, so a reader can tell where the name ends.
fn file_label_line(marker: &str, label: &str) -> String {
    let tab = if label.contains(' ') { "\t" } else { "" };
    format!("{marker} {label}{tab}")
}

/// A hunk's line range as git writes it: 1-based `start,count`, the count
/// left out when it is one, and an empty range written as the line before it.
fn hunk_range(range: &std::ops::Range<usize>) -> String {
    match range.len() {
        0 => format!("{},0", range.start),
        1 => format!("{}", range.start + 1),
        len => format!("{},{len}", range.start + 1),
    }
}

#[cfg(test)]
mod tests {
    use super::{BoundedText, hunk_range};

    /// git's spelling of a hunk range: an empty range names the line before
    /// it, a one-line range drops its count.
    #[test]
    fn a_hunk_range_is_written_as_git_writes_it() {
        assert_eq!(hunk_range(&(0..0)), "0,0");
        assert_eq!(hunk_range(&(4..4)), "4,0");
        assert_eq!(hunk_range(&(0..1)), "1");
        assert_eq!(hunk_range(&(2..5)), "3,3");
    }

    /// The bound cuts at a whole line and refuses every later line, even one
    /// short enough to fit.
    #[test]
    fn the_bound_cuts_at_a_whole_line_and_holds() {
        let mut out = BoundedText::new(8);
        assert!(out.line("abc"));
        assert!(!out.line("defgh"));
        assert!(!out.line(""));
        let diff = out.finish();
        assert_eq!(diff.text, "abc\n");
        assert!(diff.truncated);
    }
}
