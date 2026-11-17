"""e9-verdict.py: E9's verdict, generated from the files the run left (RUNBOOK §8.4, ruling R1).

    python3 -I e9-verdict.py INSTALL_RUN_DIR E9_E1_DIR > e9-verdict.txt

INSTALL_RUN_DIR is `e9-vm.sh install`'s run directory (its `sections.tsv`); E9_E1_DIR is
`e9-e1.sh run`'s OUT (its `boot-check.txt`, and `ev/oracles.txt` + `ev/score.json` from
e1-run.sh and score-e1.py). The rule, declared before any E9 run spends (RUNBOOK §8.4,
README E9): E9 PASSES when ALL of

  - `sections.tsv` lists exactly Requirements, Install from source, Quickstart and Checks,
    in that order, each rc 0 (Checks ends with the guest oracle: the Quickstart's run read
    `completed` through a second, read-only sqlite handle);
  - `boot-check.txt` reads `boot-check: ok` (the guest's node runs the bundled commit,
    built clean);
  - `ev/oracles.txt` holds e1-run.sh's eight oracle lines in order, and the seven that do
    not judge seeded recall read PASS;
  - the eighth, `review-validates-and-scores`, is judged on what does not depend on the
    model's recall: score.json's `structure_errors` and `path_errors` are both empty lists
    (the review is the schema's shape, every finding on a path at the PR's head).

The seeded recall (`seeded_found`, e.g. `2/3`) is RECORDED as observed, never a pass
condition: a clean-machine cell measures the install path, and a recall miss is the
model's, which E1 already reports per harness. Anything else is a FAIL, each reason named.
Prints the verdict file: its first line is `pass: ...` or `fail: ...` (the E9 record's
`outcome_source` is `e9-verdict.txt: <that line>`), then one line per input read.
Exit 0 on pass, 1 on fail, 2 on usage.
"""

import json
import os
import sys

SECTIONS = ["Requirements", "Install from source", "Quickstart", "Checks"]
ORACLES = ["terminal-completed", "frozen-head-is-forge-head", "review-validates-and-scores",
           "remote-unchanged", "no-target-pin-left", "stages-read", "turns-read", "spend-read"]
RECALL = "review-validates-and-scores"


def read(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError as e:
        return e


def main(argv):
    if len(argv) != 3:
        sys.stderr.write(__doc__)
        return 2
    install, e1 = argv[1], argv[2]
    fails, lines = [], []

    text = read(os.path.join(install, "sections.tsv"))
    rows = [] if isinstance(text, OSError) else [line.split("\t") for line in text.splitlines() if line]
    names = [r[0] for r in rows]
    bad = [f"{r[0]} rc {r[1] if len(r) > 1 else '?'}" for r in rows if len(r) != 2 or r[1] != "0"]
    if isinstance(text, OSError):
        fails.append(f"no install sections.tsv ({text})")
    elif names != SECTIONS:
        fails.append(f"install sections {names}, not {SECTIONS}")
    if bad:
        fails.append("install section(s) failed: " + ", ".join(bad))
    ok_sections = sum(1 for r in rows if len(r) == 2 and r[1] == "0" and r[0] in SECTIONS)
    lines.append(f"install sections.tsv: {'; '.join(f'{r[0]} rc {r[1]}' for r in rows if len(r) == 2) or 'none'}")

    boot = read(os.path.join(e1, "boot-check.txt"))
    boot_ok = not isinstance(boot, OSError) and "boot-check: ok" in boot
    if not boot_ok:
        fails.append("the boot check did not read `boot-check: ok`")
    lines.append(f"boot-check.txt: {'ok' if boot_ok else 'NOT ok'}")

    text = read(os.path.join(e1, "ev", "oracles.txt"))
    oracle_lines = [] if isinstance(text, OSError) else text.splitlines()
    def name(line):
        words = line.split(" ", 2)
        return words[1].rstrip(":") if len(words) > 1 else line

    got = [name(line) for line in oracle_lines]
    if got != ORACLES:
        fails.append(f"ev/oracles.txt names {got}, not e1-run.sh's eight in order")
    non_recall = [line for line in oracle_lines if name(line) != RECALL]
    passed = [line for line in non_recall if line.startswith("PASS ")]
    for line in non_recall:
        if not line.startswith("PASS "):
            fails.append(f"oracle: {line}")
    lines.append(f"ev/oracles.txt: {len(passed)} of {len(non_recall)} non-recall oracles PASS")

    score = read(os.path.join(e1, "ev", "score.json"))
    recall = "unread"
    valid = False
    if isinstance(score, OSError):
        fails.append(f"no ev/score.json ({score})")
    else:
        try:
            report = json.loads(score)
        except ValueError as e:
            report = None
            fails.append(f"ev/score.json does not parse: {e}")
        if isinstance(report, dict):
            recall = str(report.get("seeded_found", "unread")).split(" ", 1)[0]
            structure, paths = report.get("structure_errors"), report.get("path_errors")
            valid = structure == [] and paths == []
            if not valid:
                fails.append(f"the review does not validate: structure_errors {structure!r}, path_errors {paths!r}")
    lines.append(f"ev/score.json: structure and paths {'valid' if valid else 'NOT valid'}; "
                 f"seeded_found {recall} (recorded, not judged)")

    if fails:
        print("fail: " + "; ".join(fails))
    else:
        print(f"pass: install {ok_sections} of {len(SECTIONS)} sections rc 0; boot check ok; E1 {len(passed)} of "
              f"{len(non_recall)} non-recall oracles PASS, the review validates (structure, paths); seeded recall "
              f"{recall} recorded, not judged")
    for line in lines:
        print(line)
    print("rule (declared before the run, RUNBOOK §8.4, README E9): every install section rc 0, the boot check, "
          "the seven non-recall oracles and the review's structure and paths; seeded recall is recorded only")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
