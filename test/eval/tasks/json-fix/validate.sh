#!/usr/bin/env bash
set -euo pipefail
python3 - <<'PY'
import json
with open("config.json") as f:
    d = json.load(f)
assert d["name"] == "kata", d.get("name")
assert isinstance(d["version"], str) and d["version"], d.get("version")
assert isinstance(d["features"], list), d.get("features")
assert "a" in d["features"] and "b" in d["features"], d["features"]
print("ok")
PY
