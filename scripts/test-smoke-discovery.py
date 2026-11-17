#!/usr/bin/env python3
"""Portable discovery/readiness controls; Linux process ownership runs separately."""

import copy
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import runpy
import socket
import subprocess
import threading
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
ENDPOINT_MODULE = runpy.run_path(str(ROOT / "scripts/smoke-endpoint.py"))
ENDPOINT = ENDPOINT_MODULE["endpoint_from_records"]


class DiscoveryTests(unittest.TestCase):
    def test_ready_response_after_deadline_is_refused(self):
        with tempfile.TemporaryDirectory(prefix="kata-ready-deadline-") as directory:
            result = subprocess.run(
                ["bash", "-c", r'''
source scripts/smoke-harness.sh
tmp=$1
cfg=unused
pid=unused
api=http://127.0.0.1:0
solo_alive() { return 0; }
# Use the production function unchanged except a one-second test budget. Assert
# that substitution took effect so a source rename cannot make this vacuous.
definition=$(declare -f wait_for_api)
[[ "$definition" == *"SECONDS + 30"* ]] || exit 88
eval "${definition/SECONDS + 30/SECONDS + 1}"
timeout() { sleep 1.1; echo http://127.0.0.1:12345; }
SECONDS=0
wait_for_api late-response
''', "test", directory], cwd=ROOT, capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("API did not become ready", result.stderr)

    def test_special_and_oversized_discovery_files_refuse(self):
        with tempfile.TemporaryDirectory(prefix="kata-discovery-input-") as directory:
            root = Path(directory)
            regular = root / "regular"
            regular.write_bytes(b"{}")
            self.assertEqual(ENDPOINT_MODULE["bounded_read"](regular), b"{}")
            fifo = root / "fifo"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError, "not a regular file"):
                ENDPOINT_MODULE["bounded_read"](fifo)
            alias = root / "alias"
            alias.symlink_to(regular)
            with self.assertRaises(OSError):
                ENDPOINT_MODULE["bounded_read"](alias)
            regular.write_bytes(b"x" * (1024 * 1024 + 1))
            with self.assertRaisesRegex(ValueError, "size bound"):
                ENDPOINT_MODULE["bounded_read"](regular)

    def test_tcp_acceptance_and_wrong_generation_are_not_api_readiness(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(self.server.reply).encode())

            def log_message(self, *_args):
                pass

        with HTTPServer(("127.0.0.1", 0), Handler) as server:
            endpoint = f"http://127.0.0.1:{server.server_port}"
            metadata = {"directory_id": "directory", "process_generation": "generation",
                        "control_endpoint": endpoint}
            server.reply = dict(metadata, ready=False)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                # This is the previous footprint oracle. It passes while the
                # external status below explicitly says this is not ready.
                with socket.create_connection(server.server_address, timeout=1):
                    pass
                with self.assertRaisesRegex(ValueError, "not API-ready"):
                    ENDPOINT_MODULE["require_ready"](endpoint, metadata)
                server.reply = dict(metadata, ready=True, process_generation="other")
                with self.assertRaisesRegex(ValueError, "does not describe"):
                    ENDPOINT_MODULE["require_ready"](endpoint, metadata)
                server.reply = dict(metadata, ready=True)
                ENDPOINT_MODULE["require_ready"](endpoint, metadata)
            finally:
                server.shutdown()
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())

    def test_endpoint_discovery_requires_the_owned_identity_and_generation(self):
        identity = {"directory_id": "directory"}
        metadata = {"pid": 123, "directory_id": "directory", "process_generation": "generation",
                    "control_endpoint": "http://127.0.0.1:12345"}
        descriptor = {"directory_id": "directory", "process_generation": "generation",
                      "endpoint": "http://127.0.0.1:12345"}
        self.assertEqual(ENDPOINT(identity, metadata, descriptor, 123), descriptor["endpoint"])
        for field, value in (("directory_id", "other"), ("process_generation", "other"),
                             ("endpoint", "http://127.0.0.1:0")):
            with self.subTest(field=field):
                changed = copy.deepcopy(descriptor)
                changed[field] = value
                with self.assertRaises(ValueError):
                    ENDPOINT(identity, metadata, changed, 123)
        with self.assertRaises(ValueError):
            ENDPOINT(identity, metadata, descriptor, 456)
        zero_metadata = dict(metadata, control_endpoint="http://127.0.0.1:0")
        with self.assertRaises(ValueError):
            ENDPOINT(identity, zero_metadata, dict(descriptor, endpoint="http://127.0.0.1:0"), 123)


if __name__ == "__main__":
    unittest.main()
