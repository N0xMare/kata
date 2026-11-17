#!/usr/bin/env python3
"""Flake-drift report for the L2 nightly: this run's JUnit against the last N nightlies.

`scripts/nightly.sh` archives every run's nextest JUnit reports under
`target/nightly/<run>/junit/`. This compares the current run's reports with up to N
previous runs' and prints a Markdown section for the nightly report.

A TEST IS IDENTIFIED by nextest's `(classname, name)` pair, where the classname is the
binary id (`kata-core`, `kata::surface_inventory`) -- the same pair a
`binary_id(=...) & test(=...)` filterset selects, which is how the bisect narrows a probe.

WHAT IT FLAGS, and nothing wider:

  * SLOWER -- a test that passed now and in at least `--min-history` previous runs, whose
    duration now exceeds the MEDIAN of its previous passing durations by more than
    `--pct` percent AND by at least `--min-delta` seconds, and is itself at least
    `--min-seconds` long. The absolute floors exist because a 4 ms test that takes 9 ms
    is +125% and means nothing.
  * RETRIED -- a testcase carrying a `<flakyFailure>`/`<flakyError>` (passed on retry) or a
    `<rerunFailure>`/`<rerunError>` element, now. `.config/nextest.toml` sets `retries = 0`,
    so this is empty unless a profile or override enables retries; it is reported
    rather than assumed away.
  * INTERMITTENT -- a test whose outcome differs between runs in the window (it failed
    in some and passed in others, the current run included), i.e. a flip-flop.
  * NEW FAILURE -- failed now, and passed in every previous run that contained it.

WHAT IT CANNOT SEE: tests absent from every report (a report only holds what ran), a
slowdown in a test with too little history, and load. Durations are wall clock on a
shared host; a SLOWER row is a lead to read against the report's load figures, not a
verdict. The report never fails the nightly: exit 0 whatever it finds, 2 on unreadable
input.
"""

import argparse
import contextlib
import io
import os
import statistics
import sys
import tempfile
import xml.etree.ElementTree as ET

RETRY_TAGS = ("flakyFailure", "flakyError", "rerunFailure", "rerunError")
FAIL_TAGS = ("failure", "error")


def parse_reports(paths):
    """{(classname, name): (outcome, seconds, retried)} over every JUnit file given.

    outcome is "pass", "fail" or "skip". A test present in two files (two profiles ran
    it) keeps its worst outcome and its longest duration.
    """
    result = {}
    rank = {"skip": 0, "pass": 1, "fail": 2}
    for path in paths:
        root = ET.parse(path).getroot()
        for case in root.iter("testcase"):
            key = (case.get("classname", ""), case.get("name", ""))
            children = {child.tag for child in case}
            if children & set(FAIL_TAGS):
                outcome = "fail"
            elif "skipped" in children:
                outcome = "skip"
            else:
                outcome = "pass"
            seconds = float(case.get("time") or 0.0)
            retried = bool(children & set(RETRY_TAGS))
            if key in result:
                old = result[key]
                outcome = max(outcome, old[0], key=rank.get)
                seconds = max(seconds, old[1])
                retried = retried or old[2]
            result[key] = (outcome, seconds, retried)
    return result


def junit_files(directory):
    found = []
    for base, _dirs, files in os.walk(directory):
        found.extend(os.path.join(base, f) for f in files if f.endswith(".xml"))
    return sorted(found)


def analyse(current, history, pct, min_seconds, min_delta, min_history):
    slower, retried, intermittent, new_failures = [], [], [], []
    for key, (outcome, seconds, was_retried) in sorted(current.items()):
        past = [run[key] for run in history if key in run]
        if was_retried:
            retried.append((key, outcome))
        outcomes = {o for o, _s, _r in past if o != "skip"}
        if outcome != "skip":
            outcomes_all = outcomes | {outcome}
            if "pass" in outcomes_all and "fail" in outcomes_all:
                fails = sum(1 for o, _s, _r in past if o == "fail") + (
                    outcome == "fail"
                )
                intermittent.append((key, fails, len(past) + 1))
        if outcome == "fail" and past and outcomes == {"pass"}:
            new_failures.append((key, len(past)))
        passing = [s for o, s, _r in past if o == "pass"]
        if outcome == "pass" and len(passing) >= min_history:
            base = statistics.median(passing)
            if (
                seconds >= min_seconds
                and seconds - base >= min_delta
                and seconds > base * (1 + pct / 100.0)
            ):
                growth = (seconds / base - 1) * 100 if base > 0 else float("inf")
                slower.append((key, base, seconds, growth, len(passing)))
    slower.sort(key=lambda row: -row[3])
    return slower, retried, intermittent, new_failures


def failures(directory):
    """`group<TAB>binary_id<TAB>test` for every failed testcase, where the group is the
    directory holding the report -- nightly.sh archives each tier step's report as
    `junit/<step>/junit.xml`, so the group is the step. Listed in the report on a red."""
    rows = []
    for path in junit_files(directory):
        group = os.path.basename(os.path.dirname(path))
        for (binary, test), (outcome, _s, _r) in sorted(parse_reports([path]).items()):
            if outcome == "fail":
                rows.append(f"{group}\t{binary}\t{test}")
    return rows


def ident(key):
    return f"`{key[0]}` `{key[1]}`"


def render(current, history_count, findings, args):
    slower, retried, intermittent, new_failures = findings
    out = []
    out.append(
        f"Compared {len(current)} testcases against {history_count} previous nightly "
        f"run(s). Thresholds: slower = > {args.pct:g}% AND >= {args.min_delta:g}s over the "
        f"median of >= {args.min_history} previous passing durations, and >= "
        f"{args.min_seconds:g}s now."
    )
    out.append("")
    if history_count == 0:
        out.append(
            "No previous nightly JUnit to compare against: this run becomes the first baseline."
        )
        out.append("")
    sections = [
        (
            "New failures",
            new_failures,
            "| Test | Passed in previous runs |",
            "|---|---|",
            lambda r: f"| {ident(r[0])} | {r[1]} |",
        ),
        (
            "Intermittent (outcome flipped within the window)",
            intermittent,
            "| Test | Failed in | Of runs |",
            "|---|---|---|",
            lambda r: f"| {ident(r[0])} | {r[1]} | {r[2]} |",
        ),
        (
            "Retried now (flaky/rerun elements)",
            retried,
            "| Test | Final outcome |",
            "|---|---|",
            lambda r: f"| {ident(r[0])} | {r[1]} |",
        ),
        (
            "Slower",
            slower,
            "| Test | Median before (s) | Now (s) | Growth | Samples |",
            "|---|---|---|---|---|",
            lambda r: (
                f"| {ident(r[0])} | {r[1]:.3f} | {r[2]:.3f} | +{r[3]:.0f}% | {r[4]} |"
            ),
        ),
    ]
    for title, rows, header, rule, fmt in sections:
        out.append(f"#### {title}: {len(rows)}")
        out.append("")
        if rows:
            out.append(header)
            out.append(rule)
            out.extend(fmt(r) for r in rows[: args.max_rows])
            if len(rows) > args.max_rows:
                out.append(f"| ... {len(rows) - args.max_rows} more | |")
            out.append("")
    return "\n".join(out) + "\n"


def run(args):
    try:
        current = parse_reports(junit_files(args.current))
        history = [parse_reports(junit_files(d)) for d in args.history]
    except (ET.ParseError, OSError) as exc:
        print(f"nightly-drift: unreadable JUnit input: {exc}", file=sys.stderr)
        return 2
    history = [h for h in history if h]
    findings = analyse(
        current, history, args.pct, args.min_seconds, args.min_delta, args.min_history
    )
    text = render(current, len(history), findings, args)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    return 0


def _case(name, seconds, extra=""):
    return f'<testcase name="{name}" classname="kata-core" time="{seconds}">{extra}</testcase>'


def _write(directory, cases):
    os.makedirs(directory, exist_ok=True)
    with open(os.path.join(directory, "junit.xml"), "w", encoding="utf-8") as fh:
        fh.write('<?xml version="1.0"?><testsuites><testsuite name="kata-core">')
        fh.write("".join(cases))
        fh.write("</testsuite></testsuites>")


def self_test():
    """Synthetic JUnit: each finding class is produced exactly where planted, and not elsewhere."""
    fail = "<failure message='boom'/>"
    with tempfile.TemporaryDirectory(prefix="nightly-drift-") as tmp:
        hist = []
        for i, (steady, slow, flip) in enumerate(
            [(2.0, 1.0, ""), (2.1, 1.1, fail), (1.9, 1.0, "")]
        ):
            d = os.path.join(tmp, f"h{i}")
            _write(
                d,
                [
                    _case("steady", steady),
                    _case("grew", slow),
                    _case("tiny", 0.004),
                    _case("flipper", 0.5, flip),
                    _case("newly_broken", 0.2),
                    _case("noisy_small", 1.0),
                ],
            )
            hist.append(d)
        cur = os.path.join(tmp, "cur")
        _write(
            cur,
            [
                _case("steady", 2.2),  # +10%: under the 50% threshold
                _case("grew", 3.0),  # 1.0 -> 3.0: +200%, +2 s -> SLOWER
                _case("tiny", 0.012),  # +200% but under both absolute floors
                _case("flipper", 0.5),  # failed once in history -> INTERMITTENT
                _case(
                    "newly_broken", 0.2, fail
                ),  # passed x3, fails now -> NEW FAILURE (+ intermittent)
                _case(
                    "noisy_small", 1.6
                ),  # +60% but only +0.6 s: under --min-delta 1.0 below
                _case(
                    "retried", 0.3, "<flakyFailure message='x'/>"
                ),  # RETRIED, no history
            ],
        )
        cur_r = parse_reports(junit_files(cur))
        hist_r = [parse_reports(junit_files(d)) for d in hist]
        slower, retried, intermittent, new_failures = analyse(
            cur_r, hist_r, 50, 1.0, 1.0, 3
        )

        def names(rows):
            return sorted(r[0][1] for r in rows)

        checks = [
            ("slower", names(slower), ["grew"]),
            ("retried", names(retried), ["retried"]),
            ("intermittent", names(intermittent), ["flipper", "newly_broken"]),
            ("new_failures", names(new_failures), ["newly_broken"]),
        ]
        # min-history refusal: with only 2 previous runs nothing may be called SLOWER.
        s2, _, _, _ = analyse(cur_r, hist_r[:2], 50, 1.0, 1.0, 3)
        checks.append(("slower with 2 of 3 required samples", names(s2), []))
        # Lowering --min-delta admits exactly the planted noisy_small row.
        s3, _, _, _ = analyse(cur_r, hist_r, 50, 1.0, 0.5, 3)
        checks.append(("slower at min-delta 0.5", names(s3), ["grew", "noisy_small"]))
        # Worst outcome wins across two reports holding the same test.
        dup = os.path.join(tmp, "dup")
        # The failing report sorts FIRST, so a last-writer-wins merge would read "pass".
        _write(os.path.join(dup, "a"), [_case("same", 2.0, fail)])
        _write(os.path.join(dup, "b"), [_case("same", 1.0)])
        merged = parse_reports(junit_files(dup))
        checks.append(
            ("merge", [merged[("kata-core", "same")]], [("fail", 2.0, False)])
        )
        # --failures names exactly the failed testcases, with the report's directory.
        checks.append(("failures", failures(cur), ["cur\tkata-core\tnewly_broken"]))
        bad = [
            f"{what}: got {got!r}, want {want!r}"
            for what, got, want in checks
            if got != want
        ]
        # Unreadable input is exit 2, never a silent empty report.
        broken = os.path.join(tmp, "broken")
        os.makedirs(broken)
        with open(os.path.join(broken, "junit.xml"), "w", encoding="utf-8") as fh:
            fh.write("<testsuites><testcase")
        ns = argparse.Namespace(
            current=broken,
            history=[],
            pct=50,
            min_seconds=1,
            min_delta=0.5,
            min_history=3,
            out=None,
            max_rows=50,
        )
        with contextlib.redirect_stderr(io.StringIO()) as err:
            rc = run(ns)
        if "unreadable JUnit input" not in err.getvalue():
            bad.append(f"unreadable input: no diagnostic on stderr: {err.getvalue()!r}")
        if rc != 2:
            bad.append(f"unreadable input: rc {rc}, want 2")
    if bad:
        print("nightly-drift self-test: FAIL", file=sys.stderr)
        for line in bad:
            print(f"  {line}", file=sys.stderr)
        return 1
    print(f"nightly-drift self-test: OK ({len(checks) + 1} checks)")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--current", help="directory holding this run's JUnit files")
    parser.add_argument(
        "--history", nargs="*", default=[], help="previous runs' JUnit directories"
    )
    parser.add_argument("--pct", type=float, default=50.0)
    parser.add_argument("--min-seconds", type=float, default=1.0)
    parser.add_argument("--min-delta", type=float, default=0.5)
    parser.add_argument("--min-history", type=int, default=3)
    parser.add_argument("--max-rows", type=int, default=50)
    parser.add_argument("--out")
    parser.add_argument(
        "--failures",
        metavar="DIR",
        help="print step/binary/test of each failed testcase",
    )
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.failures:
        try:
            rows = failures(args.failures)
        except (ET.ParseError, OSError) as exc:
            print(f"nightly-drift: unreadable JUnit input: {exc}", file=sys.stderr)
            return 2
        if rows:
            print("\n".join(rows))
        return 0
    if not args.current:
        parser.error("--current is required")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
