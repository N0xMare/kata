#!/usr/bin/env python3
"""A stand-in Anthropic Messages endpoint for a NO-SPEND E3 host dry run, never a funded one.

`scripts/e9-vm.sh standin-provider` runs it INSIDE the throwaway E9 guest, after
`block-providers` mapped every provider host to 127.0.0.1 and ::1: it serves
https://api.anthropic.com/ on 127.0.0.1:<port> and [::1]:<port> (443 in the guest) under a
throwaway CA that only the guest's system store trusts, so kata's real `nanocode-anthropic`
client, with the rig's endpoint door shut, completes a turn while no request leaves the guest.
That is what P3-host needs: its crash point fires only in a COMPLETED turn's `/out`
publication, so a stand-in agent that reaches no provider VOIDs it.

Every POST to a path ending `/messages` is answered 200 with one text block as an Anthropic
SSE stream: the change pack's Plan (the E3 process column's mock `PLAN_ANSWER`) when the
request body asks for a plan (`produce a plan for the task`), else `done`. Anything else is
answered 404. Each request is appended to <log> as one JSON line (method, path, size, whether
it was the plan turn, the status answered), unsynced: a host kill may drop the last lines.

usage: e9-standin-provider.py <cert-chain.pem> <key.pem> <log> <port>
"""

import json
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PLAN_ANSWER = (
    '{"summary": "Replace the line in src/app.txt.", "steps": ["edit src/app.txt"], '
    '"files": ["src/app.txt"], "risks": []}'
)
PLAN_ASK = "produce a plan for the task"
LOG_LOCK = threading.Lock()


def log(path, entry):
    entry["t"] = time.time()
    with LOG_LOCK, open(path, "a") as out:
        out.write(json.dumps(entry) + "\n")


def stream(text):
    events = [
        {
            "type": "message_start",
            "message": {
                "id": "msg_standin",
                "type": "message",
                "role": "assistant",
                "model": "claude-sonnet-5-5",
                "content": [],
                "stop_reason": None,
                "stop_sequence": None,
                "usage": {"input_tokens": 10, "output_tokens": 1},
            },
        },
        {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text}},
        {"type": "content_block_stop", "index": 0},
        {
            "type": "message_delta",
            "delta": {"stop_reason": "end_turn", "stop_sequence": None},
            "usage": {"output_tokens": 3},
        },
        {"type": "message_stop"},
    ]
    return "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in events).encode()


def handler(log_path):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def refuse(self):
            log(log_path, {"method": self.command, "path": self.path, "answer": 404})
            self.send_response(404)
            self.send_header("content-length", "0")
            self.end_headers()

        do_GET = refuse

        def do_POST(self):
            size = int(self.headers.get("content-length", "0"))
            body = self.rfile.read(size).decode("utf-8", "replace")
            if not self.path.split("?")[0].endswith("/messages"):
                self.refuse()
                return
            plan = PLAN_ASK in body
            payload = stream(PLAN_ANSWER if plan else "done")
            log(log_path, {"method": "POST", "path": self.path, "bytes": size, "plan": plan, "answer": 200})
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    return Handler


class Server6(ThreadingHTTPServer):
    address_family = socket.AF_INET6


def main():
    if len(sys.argv) != 5:
        sys.exit(__doc__.strip().splitlines()[-1])
    cert, key, log_path, port = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    context.set_alpn_protocols(["http/1.1"])
    servers = []
    for server_class, address in ((ThreadingHTTPServer, "127.0.0.1"), (Server6, "::1")):
        server = server_class((address, port), handler(log_path))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        servers.append(server)
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
    for thread in threads:
        thread.start()
    log(log_path, {"started": True, "port": port})
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
