#!/usr/bin/env python3
"""Prove that every test a filterset selects RAN and PASSED in `just test`'s report.

`agent-accept` and `test-conformance` do not RE-RUN tests `just test` has just run. A
re-run under a `-p` list would force a separate build of `kata` through feature
unification and could see nothing the first run had not: same profile, same
default-filter, same tests. What those steps contribute is a SELECTION -- "these named
tests are part of the suite" -- and that is what this checks, against the suite's own
JUnit report, without building anything new.

It is STRONGER than a re-run in one respect and must not be read as stronger in any
other. A re-run would prove the tests pass now; `just test` exiting 0 already proves
that for every test it ran. What a re-run cannot prove is that the named tests are
among the ones `just test` ran. This proves both halves at once: every identity the
filter selects under the default profile appears in the report as a testcase with no
`<failure>`, `<error>` or `<skipped>` child.

WHAT IT CANNOT SEE, stated so nobody reads more into a pass: the report is whatever
`[profile.default.junit]` last wrote. The gate deletes it before `just test`, so inside
a tier it is that run's report. Run standalone, it vouches for the most recent default
profile run -- and says when that report was written.

Refuses: an empty selection (a filter that matches nothing proves nothing); a missing
or unparseable report; any selected identity absent from the report; any selected
identity whose testcase failed, errored or was skipped.
"""

import argparse
import importlib.util
import os
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

DEFAULT_REPORT = "target/nextest/default/junit.xml"


def _partition_module():
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location(
        "check_test_partition", os.path.join(here, "check-test-partition.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def report_outcomes(text):
    """Return {(binary_id, test): passed} from a nextest JUnit document."""
    root = ET.fromstring(text)
    if root.tag != "testsuites":
        raise ValueError(f"not a nextest JUnit report (root <{root.tag}>)")
    outcomes = {}
    for suite in root.findall("testsuite"):
        binary_id = suite.get("name")
        if not binary_id:
            raise ValueError("a <testsuite> carries no name")
        for case in suite.findall("testcase"):
            name = case.get("name")
            if not name:
                raise ValueError(f"a <testcase> in {binary_id} carries no name")
            failed = any(case.find(tag) is not None for tag in ("failure", "error", "skipped"))
            key = (binary_id, name)
            if key in outcomes:
                raise ValueError(f"duplicate testcase in report: {binary_id} {name}")
            outcomes[key] = not failed
    return outcomes


def check(selected, outcomes):
    if not selected:
        raise ValueError("the filter selected ZERO tests; an empty selection proves nothing")
    absent = sorted(k for k in selected if k not in outcomes)
    failed = sorted(k for k in selected if outcomes.get(k) is False)
    problems = [f"  did not run: {b} {t}" for b, t in absent]
    problems += [f"  did not pass: {b} {t}" for b, t in failed]
    if problems:
        raise ValueError(
            f"{len(absent) + len(failed)} of {len(selected)} selected test(s) are not "
            "vouched for by the report:\n" + "\n".join(problems)
        )


def self_test():
    def refuses(fn, *args):
        try:
            fn(*args)
        except (ValueError, ET.ParseError):
            return
        raise AssertionError("negative control was accepted")

    report = """<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="nextest-run" tests="4" failures="1" errors="0">
  <testsuite name="kata::agent_acceptance" tests="3">
    <testcase name="a" classname="kata::agent_acceptance"/>
    <testcase name="flaky" classname="kata::agent_acceptance"><flakyFailure message="x"/></testcase>
    <testcase name="bad" classname="kata::agent_acceptance"><failure message="x"/></testcase>
  </testsuite>
  <testsuite name="kata-transport" tests="1">
    <testcase name="types::conformance::x" classname="kata-transport"/>
  </testsuite>
</testsuites>"""
    outcomes = report_outcomes(report)
    a = ("kata::agent_acceptance", "a")
    flaky = ("kata::agent_acceptance", "flaky")
    bad = ("kata::agent_acceptance", "bad")
    conf = ("kata-transport", "types::conformance::x")
    check({a, flaky, conf}, outcomes)  # a retried-then-passed test PASSED
    refuses(check, {a, bad}, outcomes)  # ran and failed
    refuses(check, {a, ("kata::agent_acceptance", "never_ran")}, outcomes)  # did not run
    refuses(check, {("kata-transport", "a")}, outcomes)  # right name, wrong binary
    refuses(check, set(), outcomes)  # empty selection
    for tag in ("error", "skipped"):
        refuses(check, {a}, report_outcomes(report.replace('name="a" classname="kata::agent_acceptance"/>', f'name="a"><{tag}/></testcase>')))
    refuses(report_outcomes, "<testsuite/>")
    refuses(report_outcomes, report.replace('name="kata-transport"', ""))
    refuses(report_outcomes, report.replace("</testsuites>", '<testsuite name="kata-transport"><testcase name="types::conformance::x"/></testsuite></testsuites>'))
    refuses(report_outcomes, "not xml")
    print("junit-ran self-test: PASS (passed, retried-passed; failed, errored, skipped, absent, wrong-binary, empty, schema and duplicate controls)")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("-E", "--filter", help="nextest filterset, evaluated over --workspace under the default profile")
    parser.add_argument("--report", default=DEFAULT_REPORT)
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.filter:
        parser.error("-E/--filter is required")
    partition = _partition_module()
    # stderr is NOT discarded: `nextest list` builds, and a build error must read as
    # one rather than as "selected 0 tests".
    listing = subprocess.run(
        ["cargo", "nextest", "list", "--workspace", "-P", "default", "--message-format", "json", "-E", args.filter],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
        timeout=900,
    ).stdout
    selected = partition.selected_tests(partition.parse_listing(listing))
    try:
        with open(args.report, encoding="utf-8") as handle:
            text = handle.read()
        written = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(os.path.getmtime(args.report)))
    except OSError as error:
        raise ValueError(f"no JUnit report at {args.report} ({error}); run `just test` first") from error
    check(selected, report_outcomes(text))
    for binary_id, name in sorted(selected):
        print(f"{binary_id} {name}")
    print(
        f"junit-ran: all {len(selected)} test(s) selected by '{args.filter}' ran and passed in {args.report} (written {written})",
        file=sys.stderr,
    )


if __name__ == "__main__":
    try:
        main()
    except (ValueError, ET.ParseError, subprocess.SubprocessError, OSError) as error:
        print(f"junit-ran: FAIL — {error}", file=sys.stderr)
        sys.exit(1)
