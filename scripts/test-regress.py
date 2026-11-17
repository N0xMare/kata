#!/usr/bin/env python3
"""No cargo or git: injected nextest protocol and actual backup/restore oracles."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("regress", Path(__file__).with_name("regress.py"))
regress = importlib.util.module_from_spec(spec)
spec.loader.exec_module(regress)


def listing(names=("case",), binary="bin", ignored=False):
    return json.dumps({"rust-suites": {binary: {
        "binary-id": binary, "status": "listed", "testcases": {
            name: {"ignored": ignored, "filter-match": {"status": "matches"}}
            for name in names
        },
    }}})


def report(red=False, outcome=None, name="case"):
    child = outcome if outcome is not None else ('<failure type="test failure with exit code 101"/>' if red else '')
    return f'<testsuites><testsuite name="bin"><testcase classname="bin" name="{name}">{child}</testcase></testsuite></testsuites>'


class RegressionProof(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.base = Path(self.temp.name) / "baseline"
        self.root.mkdir()
        self.base.mkdir()
        (self.root / "fix.rs").write_bytes(b"fixed\n")
        (self.base / "fix.rs").write_bytes(b"broken\n")
        (self.root / "unrelated").write_bytes(b"user work")
        self.calls = []

    def run_proof(self, baseline_listing=None, red_exit=100, green_exit=0,
                  initial_listing=None, restored_listing=None, interrupt=False):
        count = 0

        def runner(root, expression, operation):
            nonlocal count
            self.assertEqual(expression, "test(case)")
            state = (root / "fix.rs").read_bytes()
            self.calls.append((operation, state))
            if operation == "list":
                count += 1
                data = [initial_listing, baseline_listing, restored_listing][count - 1]
                return subprocess.CompletedProcess([], 0, listing() if data is None else data)
            if interrupt and state == b"broken\n":
                raise KeyboardInterrupt()
            return subprocess.CompletedProcess([], red_exit if state == b"broken\n" else green_exit,
                                               report(red=state == b"broken\n"))

        with contextlib.redirect_stdout(io.StringIO()):
            regress.prove(self.root, self.base, "test(case)", ["fix.rs"], runner)

    def assert_restored(self):
        self.assertEqual((self.root / "fix.rs").read_bytes(), b"fixed\n")
        self.assertEqual((self.root / "unrelated").read_bytes(), b"user work")

    def test_actual_failure_then_success_restores_files(self):
        self.run_proof()
        self.assertEqual(self.calls, [
            ("list", b"fixed\n"), ("list", b"broken\n"), ("run", b"broken\n"),
            ("list", b"fixed\n"), ("run", b"fixed\n"),
        ])
        self.assert_restored()

    def test_zero_tests_on_either_side_is_not_a_regression(self):
        for keyword in ("initial_listing", "baseline_listing", "restored_listing"):
            with self.subTest(keyword=keyword), self.assertRaisesRegex(ValueError, "zero runnable"):
                self.run_proof(**{keyword: listing(())})
            self.assert_restored()

    def test_wrong_failure_exit_codes_refused(self):
        for code in (0, 4, 1, 101, 102, -15):
            with self.subTest(code=code), self.assertRaisesRegex(ValueError, "exit 100"):
                self.run_proof(red_exit=code)
            self.assert_restored()

    def test_same_count_different_binary_or_test_refused(self):
        for data in (listing(("different",)), listing(binary="different")):
            with self.subTest(data=data), self.assertRaisesRegex(ValueError, "different test identities"):
                self.run_proof(baseline_listing=data)
            self.assert_restored()

    def test_ignored_only_refused(self):
        with self.assertRaisesRegex(ValueError, "zero runnable"):
            self.run_proof(baseline_listing=listing(ignored=True))
        self.assert_restored()

    def test_malformed_listing_restores_files(self):
        for data in ("not json", '{}', '{"rust-suites":{},"rust-suites":{}}'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.run_proof(baseline_listing=data)
            self.assert_restored()

    def test_green_failure_refused(self):
        with self.assertRaisesRegex(ValueError, "fixed tests"):
            self.run_proof(green_exit=100)
        self.assert_restored()

    def test_interrupt_restores_files(self):
        with self.assertRaises(KeyboardInterrupt):
            self.run_proof(interrupt=True)
        self.assert_restored()

    def test_noop_baseline_refused(self):
        (self.base / "fix.rs").write_bytes(b"fixed\n")
        with self.assertRaisesRegex(ValueError, "byte-identical"):
            self.run_proof()
        self.assertFalse(self.calls)

    def test_install_refreshes_old_baseline_mtime_for_cargo(self):
        source, target = self.base / "fix.rs", self.root / "fix.rs"
        os.utime(source, (1, 1))
        regress.install(source, target)
        self.assertEqual(target.read_bytes(), b"broken\n")
        self.assertGreater(target.stat().st_mtime, source.stat().st_mtime)

    def test_unsafe_paths_refused(self):
        (self.root / "link").symlink_to(self.root / "fix.rs")
        for path in ("../fix.rs", "/etc/passwd", ".git/config", "link", ".", "missing"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                regress.safe_file(self.root, path)

    def test_corrupt_backup_and_concurrent_edit_preserve_recovery_files(self):
        for damage in ("backup", "target"):
            with self.subTest(damage=damage):
                backup = Path(self.temp.name) / ("recovery-" + damage)
                backup.mkdir()
                (self.root / "fix.rs").write_bytes(b"fixed\n")

                def runner(root, expression, operation):
                    if operation == "list":
                        return subprocess.CompletedProcess([], 0, listing())
                    target = backup / "0" if damage == "backup" else root / "fix.rs"
                    target.write_bytes(b"concurrent change\n")
                    return subprocess.CompletedProcess([], 100)

                with patch.object(regress.tempfile, "mkdtemp", return_value=str(backup)), \
                        contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(
                            ValueError, "manual recovery"
                        ):
                    regress.prove(self.root, self.base, "test(case)", ["fix.rs"], runner)
                self.assertTrue((backup / "manifest.json").is_file())
                self.assertEqual((self.root / "fix.rs").read_bytes(),
                                 b"broken\n" if damage == "backup" else b"concurrent change\n")

    def test_list_failure_prevents_running_tests(self):
        def runner(root, expression, operation):
            self.assertEqual(operation, "list")
            return subprocess.CompletedProcess([], 101)

        with self.assertRaisesRegex(ValueError, "list failed"):
            regress.prove(self.root, self.base, "test(case)", ["fix.rs"], runner)
        self.assert_restored()

    def test_junit_refuses_timeout_abort_skip_retry_and_missing_execution(self):
        for outcome in ('<failure type="test timeout"/>', '<error type="test abort"/>',
                        '<skipped/>', '<rerunFailure type="test failure"/>'):
            with self.subTest(outcome=outcome), self.assertRaisesRegex(ValueError, "unknown outcome"):
                regress.verify_run(subprocess.CompletedProcess([], 100, report(outcome=outcome)),
                                   {("bin", "case")}, red=True)
        for data in ('', '<testsuites/>', report(red=True, name="other"), report()):
            with self.subTest(data=data), self.assertRaises(ValueError):
                regress.verify_run(subprocess.CompletedProcess([], 100, data),
                                   {("bin", "case")}, red=True)

    def test_command_timeout_reaps_its_process_group(self):
        import sys
        with self.assertRaises(subprocess.TimeoutExpired):
            regress.bounded_command([sys.executable, "-c", "import time; time.sleep(60)"],
                                    self.root, timeout=0.05)


if __name__ == "__main__":
    unittest.main()
