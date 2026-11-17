"""spend-tally.py: the 0.0.1 round's running spend, read from kata's databases (RUNBOOK §8.5).

    python3 -I spend-tally.py SPEND_TXT --model MODEL [--next USD] [DATA_DIR...]

Every execution of every DATA_DIR (a kept node root's `data/`, a host cell's copied
`data/`, a precondition clone's `.kata/data`; none, to re-read the tally alone) is read through kit's ledger.py (`execs`,
then `record` and `stages`: a SECOND, read-only SQLite handle, nothing asked of kata), so
an execution counts whether or not a record was written for it (a void, a cell that
panicked before its record). Each becomes one line of SPEND_TXT:

    exec <execution> <model> <input> <cache_read> <cache_write> <output> <unknown_charges> <usd> <data_dir>

keyed by execution: a re-run replaces its line, never adds a second. MODEL is the model
every agent attempt of those executions declared (refused, exit 3, when `ledger.py
stages` names another): claude-sonnet-5-5 or claude-haiku-5-5, priced at Anthropic's list
price per MTok (input / output / cache read / 5-minute cache write; fetched 2026-11-11,
plan R11): sonnet $2 / $10 / $0.10 / $2.50, haiku $0.10 / $0.50 / $0.01 / $0.125; or
gpt-6-luna, the ChatGPT subscription, $0 (subscription usage, no per-token price).

An unknown charge is ledger.py's unit (`record` prints the count as `unmetered_calls`):
one attempt kata could not meter, however many model calls it issued (an E3 record's
`unknown_charges`, not its `unmetered_calls`, which counts issued calls). The total,
rewritten after the lines: every priced line's known tokens at list price, plus, per
unknown charge on a priced line, one ALLOWANCE: the largest single priced execution's known
cost in the tally, and never less than $0.25 (no per-attempt figure is on a durable row, so
the largest whole execution is the conservative stand-in for the largest unmetered
attempt). `--next USD` is the next run's worst case: when the total plus it would pass $20,
it prints `STOP: ...` and exits 4 (RUNBOOK §8.5 stop rule); otherwise exit 0. Exit 2 on
usage, 3 on a refusal (a ledger.py refusal, a model mismatch, a malformed SPEND_TXT line).
"""

import os
import re
import subprocess
import sys
import tomllib

KIT = os.path.dirname(os.path.abspath(__file__))
# USD per MTok: input, output, cache_read, cache_write (5-minute).
PRICES = {
    "claude-sonnet-5-5": (2.0, 10.0, 0.10, 2.50),
    "claude-haiku-5-5": (0.10, 0.50, 0.01, 0.125),
    "gpt-6-luna": None,
}
FLOOR = 0.25
STOP_AT = 20.0
ULID = r"[0-9A-HJKMNP-TV-Z]{26}"
LINE = re.compile(rf"^exec ({ULID}) (\S+) (\d+) (\d+) (\d+) (\d+) (\d+) ([0-9.]+) (.+)$")


class Refused(Exception):
    pass


def ledger(data_dir, *args):
    done = subprocess.run([sys.executable, "-I", os.path.join(KIT, "ledger.py"), data_dir, *args],
                          capture_output=True, text=True)
    if done.returncode != 0:
        raise Refused(f"ledger.py {data_dir} {' '.join(args)} exited {done.returncode}: {done.stderr.strip()}")
    return done.stdout


def known_usd(model, i, cr, cw, o):
    price = PRICES[model]
    if price is None:
        return 0.0
    p_in, p_out, p_cr, p_cw = price
    return (i * p_in + o * p_out + cr * p_cr + cw * p_cw) / 1e6


def read_execution(data_dir, execution, model):
    stages = ledger(data_dir, "stages", execution)
    declared = set()
    for line in stages.splitlines():
        for adapter in ("nanocode_openai", "nanocode_anthropic"):
            fields = line.split()
            if adapter in fields:
                declared.add(fields[fields.index(adapter) + 1])
    if declared - {model}:
        raise Refused(f"{execution} in {data_dir}: its agent attempts declared {sorted(declared)}, not {model}")
    spend = tomllib.loads(ledger(data_dir, "record", execution))
    t = spend["tokens_recorded"]
    counts = (t["input"], t["cache_read"], t["cache_write"], t["output"])
    # ledger.py's name for its unknown CHARGES (one per attempt), not issued calls.
    return counts, spend["unmetered_calls"]


def main(argv):
    args = argv[1:]
    nxt = None
    model = None
    try:
        if "--model" in args:
            k = args.index("--model")
            model = args[k + 1]
            del args[k:k + 2]
        if "--next" in args:
            k = args.index("--next")
            nxt = float(args[k + 1])
            del args[k:k + 2]
    except (IndexError, ValueError):
        sys.stderr.write(__doc__)
        return 2
    if model not in PRICES or len(args) < 1:
        sys.stderr.write(__doc__)
        return 2
    spend_txt, data_dirs = args[0], args[1:]
    try:
        lines = {}
        if os.path.exists(spend_txt):
            with open(spend_txt, encoding="utf-8") as fh:
                for raw in fh:
                    if not raw.startswith("exec "):
                        continue
                    m = LINE.match(raw.rstrip("\n"))
                    if not m or m.group(2) not in PRICES:
                        raise Refused(f"{spend_txt}: a malformed line: {raw.rstrip()}")
                    lines[m.group(1)] = raw.rstrip("\n")
        for data_dir in data_dirs:
            execs = [line.split()[0] for line in ledger(data_dir, "execs").splitlines()
                     if re.match(rf"{ULID}\s", line)]
            for execution in execs:
                (i, cr, cw, o), charges = read_execution(data_dir, execution, model)
                usd = known_usd(model, i, cr, cw, o)
                lines[execution] = (f"exec {execution} {model} {i} {cr} {cw} {o} {charges} {usd:.6f} "
                                    f"{os.path.abspath(data_dir)}")
    except Refused as e:
        sys.stderr.write(f"spend-tally: refused: {e}\n")
        return 3
    parsed = [LINE.match(line) for line in lines.values()]
    priced = [m for m in parsed if PRICES[m.group(2)] is not None]
    known = sum(float(m.group(8)) for m in priced)
    charges = sum(int(m.group(7)) for m in priced)
    allowance = max([FLOOR] + [float(m.group(8)) for m in priced])
    total = known + allowance * charges
    with open(spend_txt, "w", encoding="utf-8") as fh:
        fh.write("# spend-tally.py: kata's known tokens at list price, plus one allowance per unknown charge\n")
        for line in lines.values():
            fh.write(line + "\n")
        fh.write(f"known_usd = {known:.6f}\nunknown_charges = {charges}\nallowance_usd = {allowance:.6f}\n"
                 f"total_usd = {total:.6f}\n")
    print(f"spend-tally: {len(lines)} execution(s); known ${known:.6f} + {charges} unknown charge(s) x ${allowance:.6f} "
          f"= total ${total:.6f}")
    if nxt is not None:
        if total + nxt > STOP_AT:
            print(f"STOP: total ${total:.6f} + the next run's worst case ${nxt:.6f} passes ${STOP_AT:.0f}")
            return 4
        print(f"go: total ${total:.6f} + the next run's worst case ${nxt:.6f} is within ${STOP_AT:.0f}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
