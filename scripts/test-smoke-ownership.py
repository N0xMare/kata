#!/usr/bin/env python3
"""Independent process-survival controls for the shared smoke cleanup."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent


class OwnershipTests(unittest.TestCase):
    def test_product_cleanup_cannot_signal_unowned_pid(self):
        justfile = (ROOT / "justfile").read_text()
        for name in ("footprint-check ", "product-cli-smoke:"):
            with self.subTest(recipe=name), tempfile.TemporaryDirectory() as directory:
                recipe = justfile.split("\n" + name, 1)[1]
                cleanup = recipe.split("    cleanup() {\n", 1)[1].split("    trap cleanup EXIT", 1)[0]
                victim = subprocess.Popen(["sleep", "60"])
                try:
                    result = subprocess.run(
                        ["bash", "-c", 'set -eu; source scripts/smoke-harness.sh; pid="$1"; kata_pid="$1"; tmp="$2"; cleanup() {\n' + cleanup + '\ncleanup', "test", str(victim.pid), directory],
                        cwd=ROOT, capture_output=True, text=True, timeout=15,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIsNone(victim.poll(), "recipe cleanup signaled an unowned process")
                finally:
                    if victim.poll() is None:
                        victim.terminate()
                    victim.wait(timeout=5)

    def test_footprint_cleanup_preserves_unowned_attachment(self):
        recipe = (ROOT / "justfile").read_text().split("\nfootprint-check ", 1)[1]
        cleanup = recipe.split("    cleanup() {\n", 1)[1].split("    trap cleanup EXIT", 1)[0]
        # Exercise the actual cleanup body with only its owner-home operand
        # routed into this fixture; never redirect the process's real HOME.
        cleanup = cleanup.replace("$HOME", "$fixture_owner_home")
        with tempfile.TemporaryDirectory(prefix="kata-footprint-owner-") as directory:
            fixture = Path(directory)
            attachment = fixture / ".local/state/kata/main-attachment.json"
            attachment.parent.mkdir(parents=True)
            attachment.write_bytes(b"foreign synthetic attachment")
            scratch = fixture / "scratch"
            scratch.mkdir()
            result = subprocess.run(
                ["bash", "-c", 'set -eu; source scripts/smoke-harness.sh; fixture_owner_home="$1"; tmp="$2"; kata_pid=""; pgrep() { return 1; }; cleanup() {\n' + cleanup + '\ncleanup', "test", directory, str(scratch)],
                cwd=ROOT, capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(attachment.exists(), "footprint cleanup deleted an unowned attachment")
            self.assertEqual(attachment.read_bytes(), b"foreign synthetic attachment")

    def test_failed_ownership_acquisition_does_not_authorize_exit_cleanup(self):
        victim = subprocess.Popen(["sleep", "60"])
        try:
            result = subprocess.run(
                ["bash", "-c", 'set -e; source scripts/smoke-harness.sh; pid="$1"; trap terminate_solo EXIT; remember_solo', "test", str(victim.pid)],
                cwd=ROOT, capture_output=True, text=True, timeout=10,
            )
            self.assertNotEqual(result.returncode, 0, "a non-child must not acquire ownership")
            self.assertIsNone(victim.poll(), "failed acquisition retained authority to kill a stranger")
        finally:
            victim.terminate()
            victim.wait(timeout=5)

    def test_config_text_alone_never_authorizes_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="kata-smoke-owner-") as directory:
            cfg = str(Path(directory) / "config.toml")
            victim = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(60)", "--config", cfg]
            )
            try:
                result = subprocess.run(
                    ["bash", "-c", 'source scripts/smoke-harness.sh; pid=""; cfg="$1"; terminate_solo', "test", cfg],
                    cwd=ROOT, capture_output=True, text=True, timeout=10,
                )
                self.assertIsNone(victim.poll(), "cleanup killed an unowned process by config text")
                self.assertEqual(result.returncode, 0, result.stderr)
            finally:
                victim.terminate()
                victim.wait(timeout=5)

    def test_registered_child_stops_and_stale_handle_cannot_signal_another_pid(self):
        result = subprocess.run(
            ["bash", "-c", r'''
set -euo pipefail
source scripts/smoke-harness.sh
sleep 60 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true' EXIT
remember_solo
owned=$pid
terminate_solo
wait "$owned" 2>/dev/null || true
sleep 60 &
other=$!
trap 'kill "$other" 2>/dev/null || true; wait "$other" 2>/dev/null || true' EXIT
pid=$other
terminate_solo
kill -0 "$other"
'''], cwd=ROOT, capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    if not hasattr(os, "pidfd_open"):
        raise SystemExit("Linux pidfd support is required; this proof must not skip")
    unittest.main()
