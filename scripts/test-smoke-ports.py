#!/usr/bin/env python3
"""Real shell-only installed-main proof: the published endpoint owns its socket."""

import json
import os
from pathlib import Path
import pwd
import shlex
import signal
import socket
import subprocess
import tempfile
import time
import unittest
from urllib.parse import urlsplit
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parent.parent
BINARY = ROOT / "target/debug/kata"
ATTACHMENT = Path(pwd.getpwuid(os.geteuid()).pw_dir) / ".local/state/kata/main-attachment.json"


class PortTests(unittest.TestCase):
    def fixture(self, directory, port):
        root = Path(directory)
        repo = root / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "-c", "user.name=Port Test", "-c",
             "user.email=port@example.invalid", "-c", "commit.gpgsign=false",
             "-c", "core.hooksPath=/dev/null",
             "commit", "-q", "--allow-empty", "-m", "fixture"], check=True,
        )
        cfg = root / "kata.toml"
        derived = subprocess.run(
            [str(ROOT / "scripts/footprint-config.sh"), str(root / "data"), str(port), "0", str(repo)],
            check=True, capture_output=True, text=True,
        )
        cfg.write_text(derived.stdout)
        return root, cfg

    def test_ephemeral_listener_is_published_and_kept_bound(self):
        with tempfile.TemporaryDirectory(prefix="kata-port-zero-") as directory:
            root, cfg = self.fixture(directory, 0)
            workflow = root / "repo/port-zero-shell.star"
            # Under the shipped `oci` profile the stage is a capsule: it cannot
            # reach the host's listener itself — `sandbox = "host"` refuses at
            # authoring, and `INHERITED_AGENT_ENV_KEYS` (KATA_API_URL) is
            # WITHHELD from a capsule as undeclared host input.
            # What this test owns is the LISTENER claim, and the run leg's
            # share of it survives as a liveness proof: a run submitted to the
            # published endpoint dispatches a capsule and yields typed output.
            workflow.write_text(
                '''probe = stage(
    id = "probe",
    agent = "shell",
    prompt = """printf '{"bound":true}\\n'""",
    outputs = {"bound": "bool"},
)

workflow("port-zero-shell", root = [probe])
'''
            )
            subprocess.run(
                ["git", "-C", str(root / "repo"), "add", "port-zero-shell.star"], check=True
            )
            subprocess.run(
                ["git", "-C", str(root / "repo"), "-c", "user.name=Port Test",
                 "-c", "user.email=port@example.invalid", "-c", "commit.gpgsign=false",
                 "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "add shell probe"],
                check=True,
            )
            original_config = cfg.read_bytes()
            with (root / "main.log").open("w+") as log:
                child_env = os.environ.copy()
                child_env["KATA_API_URL"] = "http://127.0.0.1:0"
                # The recipe exports KATA_SERVE_WRAP as the delegated-scope
                # argv prefix (`oci_smoke_delegate_args`): an oci `serve`
                # dispatches capsules, and boot itself certifies rootless
                # cgroup delegation (`oci_route_uncertified` outside a scope).
                # The prefix ends in `--`, which makes systemd-run exec the
                # command in place — `child.pid` IS the kata pid (measured:
                # `$$` inside == `$!` outside).
                serve_wrap = shlex.split(os.environ.get("KATA_SERVE_WRAP", ""))
                child = subprocess.Popen(
                    [*serve_wrap, str(BINARY), "serve", "--config", str(cfg)],
                    cwd=ROOT,
                    env=child_env,
                    stdout=log,
                    stderr=log,
                )
                pidfd = os.pidfd_open(child.pid)
                main_pid = None
                try:
                    deadline = time.monotonic() + 30
                    descriptor = None
                    while time.monotonic() < deadline:
                        self.assertIsNone(child.poll(), "installed main exited before discovery")
                        try:
                            candidate = json.loads(ATTACHMENT.read_text())
                            identity = json.loads((root / "data/main-identity.json").read_text())
                            if candidate["directory_id"] == identity["directory_id"]:
                                descriptor = candidate
                                break
                        except FileNotFoundError:
                            pass
                        time.sleep(0.05)
                    self.assertIsNotNone(descriptor, "owned installed main did not publish discovery")
                    endpoint = urlsplit(descriptor["endpoint"])
                    self.assertNotEqual(endpoint.port, 0, "discovery published requested port 0 instead of bound socket")
                    with socket.socket() as competing:
                        with self.assertRaises(OSError):
                            competing.bind((endpoint.hostname, endpoint.port))
                    with urlopen(descriptor["endpoint"] + "/api/v1/system/status", timeout=5) as response:
                        status = json.load(response)
                    self.assertEqual(status["directory_id"], descriptor["directory_id"])
                    self.assertEqual(status["process_generation"], descriptor["process_generation"])
                    self.assertEqual(status["control_endpoint"], descriptor["endpoint"])
                    metadata = json.loads((root / "data/main.lock").read_text())
                    for field in ("directory_id", "process_generation", "control_endpoint"):
                        self.assertEqual(metadata[field], status[field])
                    main_pid = metadata["pid"]
                    # Assert the lock's pid against the filesystem, not
                    # against `child.pid`: the pid the lock names must be a
                    # live process whose executable is the binary under test
                    # — equal to `child.pid` under today's exec-in-place wrap,
                    # still true if the wrap ever grows a supervisor.
                    self.assertEqual(
                        os.readlink(f"/proc/{main_pid}/exe"),
                        str(BINARY.resolve()),
                    )
                    self.assertEqual(main_pid, child.pid)
                    self.assertEqual(cfg.read_bytes(), original_config, "runtime normalization rewrote source config")
                    self.assertEqual(status["loaded_config_path"], str(cfg.resolve()))
                    run = subprocess.run(
                        [str(BINARY), "--api-url", descriptor["endpoint"], "run", str(workflow),
                         "--wait", "--timeout-secs", "30"],
                        cwd=root / "repo", capture_output=True, text=True, timeout=45,
                    )
                    self.assertEqual(run.returncode, 0, run.stderr)
                    execution_id = json.loads(run.stdout)["id"]
                    output = subprocess.run(
                        [str(BINARY), "--api-url", descriptor["endpoint"], "run", "output",
                         execution_id, "probe"],
                        cwd=root / "repo", check=True, capture_output=True, text=True, timeout=10,
                    )
                    observed = json.loads(output.stdout)["parsed"]
                    self.assertIs(observed["bound"], True)
                finally:
                    # SIGTERM the kata pid when the lock has named it — the
                    # same process `child` waits on under the exec-in-place
                    # wrap — and the spawn pid otherwise. `RuntimeMaxSec` on
                    # the scope bounds residue either way.
                    try:
                        if main_pid is not None:
                            os.kill(main_pid, signal.SIGTERM)
                        else:
                            signal.pidfd_send_signal(pidfd, signal.SIGTERM)
                        child.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        if main_pid is not None:
                            os.kill(main_pid, signal.SIGKILL)
                        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                        child.wait(timeout=5)
                    except ProcessLookupError:
                        child.wait(timeout=5)
                    finally:
                        os.close(pidfd)

    def test_occupied_explicit_port_refuses_without_touching_competitor(self):
        with socket.socket() as competitor:
            competitor.bind(("127.0.0.1", 0))
            competitor.listen()
            port = competitor.getsockname()[1]
            with tempfile.TemporaryDirectory(prefix="kata-port-occupied-") as directory:
                root, cfg = self.fixture(directory, port)
                result = subprocess.run(
                    [str(BINARY), "serve", "--config", str(cfg)], cwd=ROOT,
                    capture_output=True, text=True, timeout=30,
                )
                self.assertNotEqual(result.returncode, 0, "occupied listener was reported ready")
                self.assertIn("listener is unavailable", result.stderr)
                self.assertFalse(ATTACHMENT.exists(), "failed boot published discovery")
                self.assertFalse((root / "data/main-identity.json").exists(), "listener refusal mutated authority")
                with socket.create_connection(("127.0.0.1", port), timeout=2):
                    connection, _ = competitor.accept()
                    connection.close()


if __name__ == "__main__":
    if os.environ.get("KATA_INSTALLED_MAIN_LOCK_HELD") != "1":
        raise SystemExit("run through scripts/installed-main-lock.sh; this proof owns installed discovery")
    unittest.main()
