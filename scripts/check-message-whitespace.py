#!/usr/bin/env python3
"""A Rust string literal must not carry a run of 3+ spaces mid-message.

THE DEFECT THIS EXISTS FOR. A long refusal or assertion message written with
its line joins collapsed — or a multi-line literal continuation that kept its
source indentation — renders prose with a wall of whitespace in the middle
(``…checkout                              conversion…``). The shape is easy
to ship (a refusal message, a capture bound message, a scope judge's verdict)
and is otherwise found by a reader instead of a guard.

WHAT IT CHECKS. Every tracked ``*.rs`` file is lexed with a small state
machine — ordinary ``"…"`` strings (which may span lines), ``//`` and nested
``/* */`` comments, char literals, raw strings — so a run is judged only
when it sits inside real string content. Inside string content, a run of
three or more spaces sitting between two "prose" characters — a lowercase
letter, digit, or clause punctuation on the left and a word-start character
on the right — is the defect. Runs that CANNOT be the defect are not
flagged:

  * a run immediately preceded by a ``\\``-escape (``\\n``, ``\\t``,
    ``\\x20``, ``\\u{…}``) is the embedded file's own indentation — a
    justfile or pack body inside a test string;
  * a run at a continued line's leading edge inside a multi-line literal,
    at the literal's opening edge (``"    "``), or trailing its last word
    is formatting, not mid-message whitespace;
  * runs whose neighbours are column-padding punctuation are deliberate
    alignment, and a banner or SQL column pad whose left neighbour is
    uppercase (``"SUITE   attack={}"``, ``"seq   INTEGER"``) is likewise.

Raw strings (``r"…"`` / ``r#"…"#``) are lexed — their content is never
misread as code — but are NOT flagged: a run inside one is verbatim text
whose meaning is the embedder's, and there is no ``\\``-continuation form
for them to have lost.

DELIBERATE mid-literal alignment — a label column like ``"name:   {}"``, an
aligned report row like ``provider   {}``, a golden table or embedded doc
block — is declared with the comment ``// kata-spacing: intentional`` on a
line the literal touches or the line immediately above its opening quote
(a ``\\``-continuation's opening line cannot carry a trailing comment —
``\\`` must end the line). The marker exempts that ONE literal only.

    python3 -B scripts/check-message-whitespace.py [--self-test]
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SEARCH_ROOTS = ("crates", "bin")
MARKER = "kata-spacing: intentional"

RUN = re.compile(r" {3,}")
# Prose boundary characters. Left: a lowercase/digit word tail or the
# punctuation that ends a clause. Right: a word, or the characters that open
# one. Uppercase on the left is deliberately excluded — it keeps banners and
# SQL column padding out without a marker.
LEFT = set("abcdefghijklmnopqrstuvwxyz0123456789:')`}.")
RIGHT = set("abcdefghijklmnopqrstuvwxyz0123456789_{(`'*—-")

CHAR_LITERAL = re.compile(r"'(\\.|[^'\\])'")
# A `\`-escape ending exactly where the run starts: the run is the embedded
# file's own indentation (e.g. `"a:\n    just test"`).
ESCAPE_BEFORE = re.compile(r"\\(?:x[0-9a-fA-F]{2}|u\{[^}]*\}|.)$")


class Literal:
    """One string literal: the (line, start, end) content segments it owns."""

    def __init__(self, start_line: int) -> None:
        self.lines = {start_line}
        self.segments: list[tuple[int, int, int]] = []

    def note(self, line: int, start: int, end: int) -> None:
        self.lines.add(line)
        if start < end:
            self.segments.append((line, start, end))


def lex_literals(text: str) -> list[Literal]:
    literals: list[Literal] = []
    pos = 0
    n = len(text)
    line = 0
    col = 0
    while pos < n:
        char = text[pos]
        if char == "\n":
            line += 1
            pos += 1
            col = 0
            continue
        if char == "/" and pos + 1 < n and text[pos + 1] == "/":
            end = text.find("\n", pos)
            if end < 0:
                break
            pos = end
            continue
        if char == "/" and pos + 1 < n and text[pos + 1] == "*":
            depth = 1
            pos += 2
            col += 2
            while pos < n and depth:
                if text.startswith("/*", pos):
                    depth += 1
                    pos += 2
                    col += 2
                elif text.startswith("*/", pos):
                    depth -= 1
                    pos += 2
                    col += 2
                elif text[pos] == "\n":
                    line += 1
                    pos += 1
                    col = 0
                else:
                    pos += 1
                    col += 1
            continue
        if char == "'":
            match = CHAR_LITERAL.match(text, pos)
            if match:
                col += match.end() - pos
                pos = match.end()
            else:
                pos += 1
                col += 1
            continue
        if char == "r" and pos + 1 < n and text[pos + 1] in '"#':
            # Raw string — consume its span so its content is never lexed as
            # code or strings; its interior is deliberately not flagged.
            probe = pos + 1
            while probe < n and text[probe] == "#":
                probe += 1
            if probe < n and text[probe] == '"':
                hashes = probe - pos - 1
                closer = '"' + "#" * hashes
                pos = probe + 1
                while pos < n and not text.startswith(closer, pos):
                    if text[pos] == "\n":
                        line += 1
                        col = 0
                    else:
                        col += 1
                    pos += 1
                pos += len(closer)
                col += len(closer)
                continue
            pos += 1
            col += 1
            continue
        if char == '"':
            literal = Literal(line)
            pos += 1
            col += 1
            seg_start = col
            while pos < n:
                if text[pos] == "\\" and pos + 1 < n and text[pos + 1] == "\n":
                    # `\` + newline (+ leading whitespace) is a line
                    # continuation — elided from the content entirely.
                    literal.note(line, seg_start, col)
                    pos += 2
                    line += 1
                    col = 0
                    while pos < n and text[pos] in " \t":
                        pos += 1
                        col += 1
                    seg_start = col
                    continue
                if text[pos] == "\\":
                    pos += 2
                    col += 2
                    continue
                if text[pos] == '"':
                    literal.note(line, seg_start, col)
                    pos += 1
                    col += 1
                    break
                if text[pos] == "\n":
                    literal.note(line, seg_start, col)
                    line += 1
                    pos += 1
                    col = 0
                    seg_start = 0
                    continue
                pos += 1
                col += 1
            literals.append(literal)
            continue
        pos += 1
        col += 1
    return literals


def scan_text(path: Path, text: str) -> list[str]:
    lines = text.splitlines()
    hits: list[str] = []
    for literal in lex_literals(text):
        touched = set(literal.lines)
        touched.add(min(literal.lines) - 1)
        if any(
            marker_line < len(lines) and MARKER in lines[marker_line]
            for marker_line in touched
        ):
            continue
        for line_no, start, end in literal.segments:
            content = lines[line_no][start:end]
            for run in RUN.finditer(content):
                left = content[run.start() - 1] if run.start() > 0 else '"'
                right = content[run.end()] if run.end() < len(content) else '"'
                if left in ('"', "\n"):
                    continue  # continuation-line indent / leading pad
                if right == '"':
                    continue  # trailing pad
                if run.start() > 0 and ESCAPE_BEFORE.search(
                    content[: run.start()]
                ):
                    continue  # the run tails a `\n`/`\x20`/… escape
                if left in LEFT and right in RIGHT:
                    excerpt = content[max(0, run.start() - 25): run.end() + 25]
                    hits.append(f"{path}:{line_no + 1}: …{excerpt.strip()}…")
                    break
            else:
                continue
            break
    return hits


def scan_file(path: Path) -> list[str]:
    return scan_text(path, path.read_text(encoding="utf8", errors="replace"))


def scan_tree(root: Path) -> list[str]:
    files = subprocess.check_output(
        ["git", "-C", str(root), "ls-files", "*.rs"], text=True
    ).splitlines()
    hits: list[str] = []
    for relative in files:
        parts = Path(relative).parts
        if "target" in parts or parts[0] not in SEARCH_ROOTS:
            continue
        hits.extend(scan_file(root / relative))
    return hits


def self_test() -> int:
    """Plant the defect in both literal shapes, plus the deliberate forms."""
    fixture = r'''
fn cell() {
    let defect = "a long refusal message whose continuation                  carries a wall";
    let multiline = "the delta writes a path declaring a checkout
conversion the profile                  does not serve";
    let marked = "name:   {}"; // kata-spacing: intentional
    let marked_block = "\
+0ms        1970-01-01 00:00:01.000Z  submitted
+1.000s     1970-01-01 00:00:02.000Z  running"; // kata-spacing: intentional
    let embedded = "recipe:\n    cargo nextest run\n";
    let hex_indent = "\x20   prompt = \"echo hi\"";
    let continued = "a folded message that wraps \
                     with a backslash continuation";
    let padding = "   ";
    let config = "node.id       = {}";
    let sql = "seq             INTEGER NOT NULL";
    let banner = "SUITE   attack={} NOTE :: {text}";
    let comment = 1; // a "quote"   inside a comment is not a literal
    let raw = r"a raw   string is verbatim";
    let _ = (defect, multiline, marked, marked_block, embedded, hex_indent,
             continued, padding, config, sql, banner, comment, raw);
}
'''
    with tempfile.TemporaryDirectory() as directory:
        probe = Path(directory) / "probe.rs"
        probe.write_text(fixture)
        hits = scan_file(probe)
        if len(hits) != 2:
            print(
                "message-whitespace self-test: FAIL — expected exactly the two "
                "planted defects (single-line and multi-line literal), got "
                f"{hits}"
            )
            return 1
    print(
        "message-whitespace self-test: ok — single-line and multi-line planted "
        "defects refused; marker (line and block literal), \\n-\\x-embedded, "
        "\\-continuation, all-space, config/SQL/banner alignment, raw strings "
        "and comment quotes all clean"
    )
    return 0


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return self_test()
    hits = scan_tree(ROOT)
    if hits:
        print(
            "message-whitespace check: a string literal carries 3+ mid-message "
            "spaces — the lost-line-continuation defect"
        )
        for hit in hits:
            print(f"  {hit}")
        print(
            "fix the literal (a `\\`-continuation if it should wrap), or mark "
            f"deliberate alignment with `// {MARKER}` on a line the literal "
            "touches"
        )
        return 1
    print("message-whitespace check: ok — no mid-message space runs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
