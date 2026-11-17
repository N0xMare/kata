#!/usr/bin/env python3
"""Discover this smoke's bound endpoint; never guess an available TCP port."""

import json
import os
from pathlib import Path
import pwd
import stat
import sys
import tomllib
from urllib.parse import urlsplit
from urllib.request import urlopen


def endpoint_from_records(identity, metadata, descriptor, pid):
    if metadata["pid"] != pid:
        raise ValueError("main lock belongs to another process")
    for field in ("directory_id", "process_generation", "control_endpoint"):
        descriptor_field = "endpoint" if field == "control_endpoint" else field
        if metadata[field] != descriptor[descriptor_field]:
            raise ValueError("attachment does not describe the owned main")
    if identity["directory_id"] != metadata["directory_id"]:
        raise ValueError("data-directory identity does not match the owned main")
    endpoint = descriptor["endpoint"]
    address = urlsplit(endpoint)
    if address.scheme != "http" or address.hostname != "127.0.0.1" or not address.port:
        raise ValueError("smoke endpoint must be a resolved loopback HTTP listener")
    if address.username or address.password or address.path or address.query or address.fragment:
        raise ValueError("unexpected smoke endpoint components")
    return endpoint


def bounded_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError("smoke discovery input is not a regular file")
        content = source.read(1024 * 1024 + 1)
    if len(content) > 1024 * 1024:
        raise ValueError("smoke discovery input exceeds size bound")
    return content


def require_ready(endpoint, metadata):
    with urlopen(endpoint + "/api/v1/system/status", timeout=1) as response:
        content = response.read(1024 * 1024 + 1)
    if len(content) > 1024 * 1024:
        raise ValueError("smoke status exceeds size bound")
    status = json.loads(content)
    if status.get("ready") is not True:
        raise ValueError("owned main is not API-ready")
    for field in ("directory_id", "process_generation", "control_endpoint"):
        if status.get(field) != metadata[field]:
            raise ValueError("API status does not describe the owned main")


def discover(config_path, pid, ready=False):
    config_path = Path(config_path).resolve()
    config = tomllib.loads(bounded_read(config_path).decode())
    data = Path(config["node"]["data_dir"]).expanduser()
    if not data.is_absolute():
        data = config_path.parent / data
    attachment = Path(pwd.getpwuid(os.geteuid()).pw_dir) / ".local/state/kata/main-attachment.json"
    metadata = json.loads(bounded_read(data / "main.lock"))
    endpoint = endpoint_from_records(
        json.loads(bounded_read(data / "main-identity.json")),
        metadata,
        json.loads(bounded_read(attachment)), pid,
    )
    if ready:
        require_ready(endpoint, metadata)
    return endpoint


if __name__ == "__main__":
    try:
        print(discover(sys.argv[1], int(sys.argv[2]), ready="--ready" in sys.argv[3:]))
    except (OSError, ValueError, KeyError, IndexError) as error:
        print(f"smoke endpoint not ready: {error}", file=sys.stderr)
        sys.exit(1)
