#!/usr/bin/env python3
"""Check runnable nextest identities, not totals or human-readable output lines."""

import argparse
import copy
import json
import subprocess
import sys

MEASUREMENT = (
    "kata-core::operational_write_measurement",
    "persistent_current_writer_reports_serialized_transaction_latency_and_throughput",
)
CORRECTNESS_FIXTURE = (
    "kata-core::operational_write_measurement",
    "persistent_current_writer_lifecycle_is_verified_by_raw_sql_after_reopen",
)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_listing(text):
    return json.loads(text, object_pairs_hook=unique_object)


def selected_tests(document):
    """Return nonignored, matching (binary_id, test_name) identities; fail closed."""
    if not isinstance(document, dict) or not isinstance(
        document.get("rust-suites"), dict
    ):
        raise ValueError("missing rust-suites object")
    selected = set()
    for binary_id, suite in document["rust-suites"].items():
        if (
            not binary_id
            or not isinstance(suite, dict)
            or suite.get("binary-id") != binary_id
        ):
            raise ValueError("invalid suite identity")
        status = suite.get("status")
        if status in ("skipped", "skipped-default-filter"):
            if suite.get("testcases") != {}:
                raise ValueError("skipped suite must carry an empty testcase object")
            continue
        if status != "listed" or not isinstance(suite.get("testcases"), dict):
            raise ValueError(f"unrecognized suite status/shape: {binary_id}")
        for name, case in suite["testcases"].items():
            if (
                not name
                or not isinstance(case, dict)
                or type(case.get("ignored")) is not bool
            ):
                raise ValueError("invalid testcase")
            match = case.get("filter-match")
            if not isinstance(match, dict) or match.get("status") not in (
                "matches",
                "mismatch",
            ):
                raise ValueError("unrecognized testcase filter status")
            if match["status"] == "matches" and not case["ignored"]:
                selected.add((binary_id, name))
    return selected


def check_partition(all_tests, default, soak, measurement):
    if not all_tests or not default or not soak or not measurement:
        raise ValueError("all, default, soak and measurement must each select runnable tests")
    overlap = (default & soak) | (default & measurement) | (soak & measurement)
    selected = default | soak | measurement
    missing = all_tests - selected
    extra = selected - all_tests
    if overlap or missing or extra:
        raise ValueError(
            f"overlap={sorted(overlap)!r}; missing={sorted(missing)!r}; extra={sorted(extra)!r}"
        )


def list_selected(*args):
    result = subprocess.run(
        ["cargo", "nextest", "list", "--workspace", "--message-format", "json", *args],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
        timeout=900,
    )
    return selected_tests(parse_listing(result.stdout))


def check_measurement(default, measurement):
    if measurement != {MEASUREMENT}:
        raise ValueError(f"unexpected measurement identities: {sorted(measurement)!r}")
    if CORRECTNESS_FIXTURE not in default:
        raise ValueError("ordinary suite lost the small raw-SQL writer correctness fixture")


def self_test():
    def refuses(fn, *args):
        try:
            fn(*args)
        except (ValueError, TypeError):
            return
        raise AssertionError("negative control was accepted")

    a, b, c, d = (("bin", name) for name in "abcd")
    check_partition({a, b, c, d}, {a, b}, {c}, {d})
    # Same totals as a correct partition, but one duplicate and one omission.
    refuses(check_partition, {a, b, c, d}, {a, b}, {b}, {d})
    refuses(check_partition, {a, b, d}, {a}, {c}, {d})
    refuses(check_partition, {a, b, c, d}, {a}, {b}, {d})
    refuses(check_partition, set(), set(), set(), set())
    refuses(check_partition, {a, d}, {a}, set(), {d})
    refuses(check_partition, {a, b, c}, {a}, {b}, set())
    refuses(check_partition, {a, b, c}, {a}, {b}, {a, c})
    refuses(check_partition, {a, b, c}, {a}, {b}, {b, c})
    ordinary = {CORRECTNESS_FIXTURE}
    measured = {MEASUREMENT}
    check_measurement(ordinary, measured)
    refuses(check_measurement, ordinary, measured | {a})
    refuses(check_measurement, ordinary, set())
    refuses(check_measurement, ordinary, {("wrong-binary", MEASUREMENT[1])})
    refuses(check_measurement, set(), measured)
    doc = {
        "rust-suites": {
            "bin": {
                "binary-id": "bin",
                "status": "listed",
                "testcases": {
                    "a": {"ignored": False, "filter-match": {"status": "matches"}},
                    "b": {"ignored": False, "filter-match": {"status": "mismatch"}},
                    "c": {"ignored": True, "filter-match": {"status": "matches"}},
                },
            }
        }
    }
    assert selected_tests(doc) == {a}
    for status in ("skipped", "skipped-default-filter"):
        skipped = copy.deepcopy(doc)
        skipped["rust-suites"]["bin"].update(status=status, testcases={})
        assert selected_tests(skipped) == set()
        for cases in (None, [], doc["rust-suites"]["bin"]["testcases"]):
            skipped["rust-suites"]["bin"]["testcases"] = cases
            refuses(selected_tests, skipped)
    duplicate_name = copy.deepcopy(doc)
    duplicate_name["rust-suites"]["second"] = copy.deepcopy(doc["rust-suites"]["bin"])
    duplicate_name["rust-suites"]["second"]["binary-id"] = "second"
    assert selected_tests(duplicate_name) == {a, ("second", "a")}
    for bad in ({}, [], {"rust-suites": []}):
        refuses(selected_tests, bad)
    for field, value in (
        ("ignored", "false"),
        ("filter-match", {"status": "unknown"}),
        ("filter-match", {}),
    ):
        bad = copy.deepcopy(doc)
        bad["rust-suites"]["bin"]["testcases"]["a"][field] = value
        refuses(selected_tests, bad)
    bad = copy.deepcopy(doc)
    bad["rust-suites"]["bin"]["status"] = "unknown"
    refuses(selected_tests, bad)
    refuses(parse_listing, '{"rust-suites": {}, "rust-suites": {}}')
    refuses(parse_listing, '{"rust-suites": {"bin": {}, "bin": {}}}')
    refuses(parse_listing, "not json")
    print(
        "test-partition self-test: PASS (three-lane identity partition, overlap+omission, extra, empty, exact measurement, ordinary writer fixture, filters, ignored, schema and duplicate JSON controls)"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    all_tests = list_selected("-P", "default", "--ignore-default-filter")
    default = list_selected("-P", "default")
    soak = list_selected("-P", "soak")
    measurement = list_selected("-P", "measurement")
    check_partition(all_tests, default, soak, measurement)
    check_measurement(default, measurement)
    print(
        f"soak-lane-invariant: OK — disjoint default={len(default)} + soak={len(soak)} + measurement={len(measurement)} exactly cover all={len(all_tests)} runnable test identities"
    )


if __name__ == "__main__":
    try:
        main()
    except (ValueError, subprocess.SubprocessError, OSError) as error:
        print(f"test-partition: FAIL — {error}", file=sys.stderr)
        sys.exit(1)
