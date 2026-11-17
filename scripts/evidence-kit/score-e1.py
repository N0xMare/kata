"""score-e1.py: validate a kata `review` result and score it against seeded.json.

    python3 -I score-e1.py REVIEW_JSON SEEDED_JSON [--repo DIR --head REV]

REVIEW_JSON is the Review object, per D2 4.1: the `parsed` member of the stage
output envelope `kata run output <exec> verify` prints (not the envelope):
  {"verdict": "approve"|"request_changes"|"comment", "summary": str,
   "findings": [{"path": str, "line": int >= 0, "severity":
                 "blocker"|"major"|"minor"|"nit", "message": str}]}

Checks (D2 5.2):
  structure  the verdict enum holds; summary is a string of at most 4000
             chars; each finding has path/line/severity/message with the
             types above (message at most 2000 chars). Unknown keys are
             reported as warnings, not errors.
  paths      with --repo/--head: every finding's path is in
             `git ls-tree -r --name-only HEAD` of that repo.
  seeded     every seeded defect is matched by a DISTINCT finding with the
             same path and `line` inside its line_range (a maximum one-to-one
             matching, so one finding cannot cover two defects).

Prints a JSON report on stdout and one row on stderr; exits 0 only when
structure, paths (if asked) and every seeded defect pass. Severity is
reported, not scored. The row and `seeded_found` read
`<found>/<seeded> (unmatched <u> of <n> findings)`: matching is by path and
line only, so an answer with a finding on every line finds every seeded
defect, and only the unmatched count shows it. Quote the whole row.

For E1(b) (a public PR, nothing seeded) pass `seeded-public.json` (`[]`): the
structure and path checks still run, and the row reads `0/0 (unmatched n of n
findings)`.

    python3 -I score-e1.py --self-test   # synthetic answers, the blanket one included
"""

import json
import subprocess
import sys

VERDICTS = {"approve", "request_changes", "comment"}
SEVERITIES = {"blocker", "major", "minor", "nit"}
FINDING_KEYS = {"path", "line", "severity", "message"}


class DuplicateKey(ValueError):
    pass


def no_duplicates(pairs):
    """object_pairs_hook: refuse an object that names a key twice."""
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise DuplicateKey(f"duplicate key {key!r}")
        seen[key] = value
    return seen


def load_json(path, what):
    """Parse PATH strictly: duplicate keys and NaN/Infinity are refused."""
    def no_constant(name):
        raise ValueError(f"non-JSON constant {name}")
    try:
        with open(path) as fh:
            return json.load(fh, object_pairs_hook=no_duplicates, parse_constant=no_constant), None
    except (OSError, ValueError) as e:
        return None, f"{what} {path}: {e}"


def structure_errors(review):
    errors, warnings = [], []
    if not isinstance(review, dict):
        return ["the review is not a JSON object"], warnings
    for key in sorted(set(review) - {"verdict", "summary", "findings"}):
        warnings.append(f"unknown top-level key {key!r}")
    if review.get("verdict") not in VERDICTS:
        errors.append(f"verdict {review.get('verdict')!r} is not one of {sorted(VERDICTS)}")
    summary = review.get("summary")
    if not isinstance(summary, str) or len(summary) > 4000:
        errors.append("summary is not a string of at most 4000 chars")
    findings = review.get("findings")
    if not isinstance(findings, list):
        errors.append("findings is not a list")
        return errors, warnings
    for i, f in enumerate(findings):
        where = f"findings[{i}]"
        if not isinstance(f, dict):
            errors.append(f"{where} is not an object")
            continue
        for key in sorted(FINDING_KEYS - set(f)):
            errors.append(f"{where} lacks {key!r}")
        for key in sorted(set(f) - FINDING_KEYS):
            warnings.append(f"{where} has unknown key {key!r}")
        if "path" in f and (not isinstance(f["path"], str) or not f["path"]):
            errors.append(f"{where}.path is not a non-empty string")
        line = f.get("line")
        if "line" in f and (isinstance(line, bool) or not isinstance(line, int) or line < 0):
            errors.append(f"{where}.line is not an integer >= 0")
        if "severity" in f and f["severity"] not in SEVERITIES:
            errors.append(f"{where}.severity {f['severity']!r} is not one of {sorted(SEVERITIES)}")
        message = f.get("message")
        if "message" in f and (not isinstance(message, str) or len(message) > 2000):
            errors.append(f"{where}.message is not a string of at most 2000 chars")
    return errors, warnings


def match(seeded, findings):
    """Maximum one-to-one matching of seeded defects to findings (Kuhn)."""
    hits = []
    for d in seeded:
        a, b = d["line_range"]
        hits.append([j for j, f in enumerate(findings)
                     if isinstance(f, dict) and f.get("path") == d["path"]
                     and isinstance(f.get("line"), int) and not isinstance(f.get("line"), bool)
                     and a <= f["line"] <= b])
    owner = {}

    def augment(i, seen):
        for j in hits[i]:
            if j in seen:
                continue
            seen.add(j)
            if j not in owner or augment(owner[j], seen):
                owner[j] = i
                return True
        return False

    for i in range(len(seeded)):
        augment(i, set())
    return {i: j for j, i in owner.items()}, hits


def main(argv):
    args = argv[1:]
    repo = head = None
    if "--repo" in args:
        k = args.index("--repo")
        repo = args[k + 1]
        del args[k:k + 2]
    if "--head" in args:
        k = args.index("--head")
        head = args[k + 1]
        del args[k:k + 2]
    if len(args) != 2 or (repo is None) != (head is None):
        sys.stderr.write("usage: score-e1.py REVIEW_JSON SEEDED_JSON [--repo DIR --head REV]\n")
        return 2
    seeded, err = load_json(args[1], "seeded")
    if err:
        sys.stderr.write(f"score-e1: {err}\n")
        return 2
    review, err = load_json(args[0], "review")
    if err:
        row = f"0/{len(seeded)} (unmatched 0 of 0 findings)"
        json.dump({"ok": False, "structure_errors": [err], "seeded_found": row}, sys.stdout, indent=2)
        sys.stdout.write("\n")
        sys.stderr.write(f"score-e1: FAIL seeded {row}; the review did not parse\n")
        return 1

    errors, warnings = structure_errors(review)
    findings = review.get("findings") if isinstance(review, dict) and isinstance(review.get("findings"), list) else []

    path_errors = []
    if repo is not None:
        listed = subprocess.run(["git", "-C", repo, "ls-tree", "-r", "--name-only", head],
                                capture_output=True, text=True)
        if listed.returncode != 0:
            path_errors.append(f"git ls-tree {head} in {repo} failed: {listed.stderr.strip()}")
        tree = set(listed.stdout.splitlines())
        for i, f in enumerate(findings):
            if isinstance(f, dict) and isinstance(f.get("path"), str) and f["path"] not in tree:
                path_errors.append(f"findings[{i}].path {f['path']!r} is not in {head}")

    matched, hits = match(seeded, findings)
    defects = []
    for i, d in enumerate(seeded):
        j = matched.get(i)
        defects.append({
            "path": d["path"], "line_range": d["line_range"], "defect": d["defect"],
            "matched": j is not None,
            "finding": None if j is None else {"index": j, "line": findings[j].get("line"),
                                               "severity": findings[j].get("severity")},
            "candidates": hits[i],
        })
    found = sum(1 for d in defects if d["matched"])
    unmatched = len(findings) - found
    # The row carries the unmatched count, so a blanket answer (a finding on every
    # line) cannot be quoted as a bare 3/3.
    row = f"{found}/{len(seeded)} (unmatched {unmatched} of {len(findings)} findings)"
    ok = not errors and not path_errors and found == len(seeded)
    report = {
        "ok": ok,
        "structure_errors": errors,
        "warnings": warnings,
        "path_errors": path_errors if repo is not None else "not checked (no --repo/--head)",
        "verdict": review.get("verdict") if isinstance(review, dict) else None,
        "findings": len(findings),
        "seeded_found": row,
        "unmatched_findings": unmatched,
        "defects": defects,
    }
    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")
    sys.stderr.write(f"score-e1: {'ok' if ok else 'FAIL'} seeded {row}\n")
    return 0 if ok else 1


def self_test():
    """Score synthetic answers against a synthetic seeded list; no repository needed."""
    import io
    import tempfile
    from contextlib import redirect_stderr, redirect_stdout

    seeded = [{"path": "lib/x.sh", "line_range": [33, 35], "defect": "a"},
              {"path": "lib/x.sh", "line_range": [32, 32], "defect": "b"},
              {"path": "lib/x.sh", "line_range": [17, 22], "defect": "c"}]

    def finding(line, path="lib/x.sh"):
        return {"path": path, "line": line, "severity": "minor", "message": "m"}

    cases = [
        # (label, findings, want exit, want seeded_found)
        ("exact answer", [finding(34), finding(32), finding(20)], 0, "3/3 (unmatched 0 of 3 findings)"),
        # The blanket answer: one finding on every line of the file finds every seeded
        # defect; the row must say so, not read a bare 3/3.
        ("blanket answer", [finding(n) for n in range(1, 61)], 0, "3/3 (unmatched 57 of 60 findings)"),
        ("one finding cannot cover two defects", [finding(32), finding(34)], 1, "2/3 (unmatched 0 of 2 findings)"),
        ("wrong path", [finding(34, "lib/y.sh")], 1, "0/3 (unmatched 1 of 1 findings)"),
        ("no findings", [], 1, "0/3 (unmatched 0 of 0 findings)"),
    ]
    ok = True
    with tempfile.TemporaryDirectory() as tmp:
        seeded_path = f"{tmp}/seeded.json"
        with open(seeded_path, "w") as fh:
            json.dump(seeded, fh)
        for label, findings, want_rc, want_found in cases:
            review_path = f"{tmp}/review.json"
            with open(review_path, "w") as fh:
                json.dump({"verdict": "request_changes", "summary": "s", "findings": findings}, fh)
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc = main(["score-e1.py", review_path, seeded_path])
            report = json.loads(out.getvalue())
            got = (rc, report.get("seeded_found"))
            if got != (want_rc, want_found):
                ok = False
                print(f"FAIL {label}: got (exit, seeded_found) {got!r}, want {(want_rc, want_found)!r}")
            elif want_found not in err.getvalue():
                ok = False
                print(f"FAIL {label}: the stderr row {err.getvalue().strip()!r} does not carry {want_found!r}")
    print(f"score-e1 self-test: {'PASS' if ok else 'FAIL'} ({len(cases)} cases)")
    return 0 if ok else 1


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        sys.exit(self_test())
    sys.exit(main(sys.argv))
