"""e3-finish.py: finish one funded E3 record the rig wrote (RUNBOOK §8.2), from outside kata.

    python3 -I e3-finish.py RECORD_DIR DATA_DIR|- [--provider-tokens I,CR,CW,O --provider-cost $X]

RECORD_DIR is one `e3-<case>-<harness>-<started>` directory under KATA_E3_EVIDENCE_DIR;
DATA_DIR is the data directory of the node root the rig KEPT for that cell
(`KATA_E2E_KEEP=1`; the nextest log names each root, `KATA_E2E_KEEP: node root kept at
<root>`, and the data directory is `<root>/data`), or, for a host cell, the guest's copy.
DATA_DIR is `-` exactly for a VOID record whose oracle.txt names no execution (the cell
voided before it submitted: nothing ran, nothing was charged).

It refuses (exit 3) a `nanocode-mock` record (a no-spend dry run is never evidence), a
judged record whose oracle.txt does not name exactly one execution, a void record naming
more than one, `-` for a record naming an execution and a DATA_DIR for one naming none,
and a DATA_DIR that does not hold exactly the named execution. Then it reads the
execution's spend through kit's ledger.py (`record`: a SECOND, read-only SQLite handle,
nothing asked of kata).

Two counts of unknown usage, in two units, each in its own field:
  unmetered_calls  the rig's: the model calls the client-side transcript shows ISSUED whose
                   usage is unknown (README E3: "the number of issued calls whose usage is
                   unknown"); every call of a killed attempt, since its usage is on no
                   durable row;
  unknown_charges  ledger.py's: one per attempt kata could not meter (ledger.py `record`
                   prints this count under the name `unmetered_calls`; this script writes it
                   as `unknown_charges`, in the record and in spend-ledger.toml).
One killed attempt is one charge however many calls it issued (P3's plan turn: 4 calls, 1
charge), and P1's killed attempt was placed and never sent (1 charge, 0 calls). So the two
are related only by this rule, whose refused set is exactly (`counts_problem`):
  - on P1 and P1-host (the unsent cases), every pair with unmetered_calls != 0, whatever
    unknown_charges (>= 0) is: the killed attempt was never sent, so it issued no call;
  - in every other case, an issued call of unknown usage with no unknown charge
    (unmetered_calls > 0, unknown_charges = 0): a call is inside an attempt, and an attempt
    with a call kata did not meter is an unknown charge; and fewer issued calls than charges
    (unmetered_calls < unknown_charges, 0 calls beside a charge included): every killed
    attempt of those cases was sent, so each unknown charge issued at least one call.

A JUDGED record (pass or fail): it refuses a `tokens_recorded` that differs from ledger.py's
known part, and counts the rule above refuses.

A VOID record: the rig judged nothing and wrote `tokens_recorded = "unknown"` and
`unmetered_calls = 0` (`Cell::record_in`, `Ended::Void`), though kata may have charged the
execution. `tokens_recorded` becomes ledger.py's known part and `unknown_charges` its
charges; `unmetered_calls` becomes a LOWER BOUND on the issued calls of unknown usage, since
no reader counted them: one per unknown charge (the rule's own floor), 0 on P1 and P1-host
(whose killed attempt may have issued none). The artifact's `what` says so. A void record
that already carries counts (a re-run) must carry exactly these (refused otherwise). A void
naming no execution keeps `unknown` and 0 issued calls, gets `unknown_charges = 0` (nothing
ran, nothing was charged) and the provider fields.

It then rewrites, in place, only these fields:
  tokens_provider, cost_provider   the rig's placeholder ("read from the provider by the
                   operator after the run") becomes the ruled value: on a subscription,
                   `unavailable: a subscription login has no per-token view` and
                   `unavailable: subscription`; under an API key, `unavailable: per-run
                   provider usage not attributable` (both), unless --provider-tokens and
                   --provider-cost give the provider's own figures read for this run alone;
  cost_recorded, cost_recorded_usd kata's own cost as ledger.py reads it: `estimated` with
                   the sum when every charge is kata's Estimated (nanocode-anthropic under an
                   API key, no unknown charge), else `unavailable`;
  unknown_charges  ledger.py's unknown charges (0 on a void naming no execution), added
                   beside unmetered_calls; a record that already states it must state exactly
                   that (refused otherwise);
  tokens_recorded, unmetered_calls  on a void naming an execution only, as above;
and adds `spend-ledger.toml` (ledger.py's output, its `unmetered_calls` line renamed
`unknown_charges` under a comment saying so) to the directory and to `artifacts` (not on a
void naming no execution), or rewrites that artifact's `what` when it already lists it.
Every other key must read back unchanged (refused otherwise); a re-run over a finished
record changes nothing. Exit 0 on success, 2 on usage, 3 on a refusal.
"""

import os
import re
import subprocess
import sys
import tomllib

KIT = os.path.dirname(os.path.abspath(__file__))
PLACEHOLDER = "unavailable: read from the provider by the operator after the run"
SUBSCRIPTION = ("unavailable: a subscription login has no per-token view", "unavailable: subscription")
API_KEY = ("unavailable: per-run provider usage not attributable",) * 2


class Refused(Exception):
    pass


def execution_of(record_dir, void):
    """The one execution oracle.txt names; None on a void that names none."""
    with open(os.path.join(record_dir, "oracle.txt"), encoding="utf-8") as fh:
        ids = set(re.findall(r"\bexecution ([0-9A-HJKMNP-TV-Z]{26})\b", fh.read()))
    if void and not ids:
        return None
    if len(ids) != 1:
        raise Refused(f"oracle.txt names {len(ids)} executions, want exactly 1")
    return ids.pop()


def ledger(data_dir, *args):
    done = subprocess.run([sys.executable, "-I", os.path.join(KIT, "ledger.py"), data_dir, *args],
                          capture_output=True, text=True)
    if done.returncode != 0:
        raise Refused(f"ledger.py {' '.join(args)} exited {done.returncode}: {done.stderr.strip()}")
    return done.stdout


def toml_line(key, value):
    if isinstance(value, str):
        return f'{key} = "{value}"\n'
    return f"{key} = {value}\n"


TOKEN_KEYS = ("cache_read", "cache_write", "input", "output")
# The cases whose killed attempt was placed and never sent: it issued no call, and its unknown
# charges may be any count (README E3: "zero model calls for that attempt").
UNSENT_CASES = ("P1", "P1-host")
LEDGER_COUNT = "unmetered_calls = "
SPEND_LEDGER_NOTE = ("# e3-finish.py: ledger.py prints its unknown CHARGES (one per attempt kata could not meter) "
                     "as `unmetered_calls`; here they are `unknown_charges`, not issued calls\n")


def tokens_table(tokens):
    """The [tokens_recorded] table as the rig's toml serializer writes it (keys sorted)."""
    return "\n[tokens_recorded]\n" + "".join(f"{k} = {tokens[k]}\n" for k in TOKEN_KEYS)


def counts_problem(case, calls, charges):
    """Why `calls` issued calls of unknown usage cannot stand beside `charges` unknown charges
    in `case`, or None. Refused: in UNSENT_CASES, calls != 0 (charges may be any count);
    elsewhere, calls > 0 beside charges == 0, and calls < charges (the rule in this script's
    header)."""
    if case in UNSENT_CASES:
        if calls != 0:
            return (f"the record's {calls} issued call(s) of unknown usage (unmetered_calls) on {case}, whose "
                    f"killed attempt is never sent: it issued 0 calls, beside ledger.py's {charges} unknown_charges "
                    "or any other count")
        return None
    if calls > 0 and charges == 0:
        return (f"the record's {calls} issued call(s) of unknown usage (unmetered_calls) beside ledger.py's 0 "
                "unknown_charges: a call is inside an attempt, and an attempt with a call kata did not meter "
                "is an unknown charge")
    if calls < charges:
        return (f"the record's {calls} issued call(s) of unknown usage (unmetered_calls) are fewer than ledger.py's "
                f"{charges} unknown_charges: outside P1 and P1-host every killed attempt was sent, so each unknown "
                "charge issued at least one call")
    return None


def void_calls(case, charges):
    """A void's lower bound on its issued calls of unknown usage, which no reader counted."""
    return 0 if case in UNSENT_CASES else charges


def renamed_spend_ledger(spend_text):
    """ledger.py's `record` output with its one charge-count line named for its unit."""
    lines = spend_text.splitlines(keepends=True)
    hits = [i for i, line in enumerate(lines) if line.startswith(LEDGER_COUNT)]
    if len(hits) != 1:
        raise Refused(f"ledger.py record printed {len(hits)} `{LEDGER_COUNT.strip()}` lines, want exactly 1")
    i = hits[0]
    lines[i] = SPEND_LEDGER_NOTE + "unknown_charges = " + lines[i][len(LEDGER_COUNT):]
    return "".join(lines)


def spend_ledger_what(void, case):
    what = ("ledger.py record over the kept node's database (a second, read-only handle): the known tokens, "
            "the unknown charges (unknown_charges: one per attempt kata could not meter) and kata's cost")
    if not void:
        return what
    bound = ("0 on this case, whose killed attempt may have issued none" if case in UNSENT_CASES
             else "one per unknown charge")
    return (what + "; on this void record, tokens_recorded and unknown_charges are these, and unmetered_calls "
            f"is a LOWER BOUND on the issued calls of unknown usage, which no reader counted ({bound})")


def finish(record_dir, data_dir, provider):
    path = os.path.join(record_dir, "run.toml")
    with open(path, "rb") as fh:
        before = tomllib.load(fh)
    if before.get("cell") != "E3" or before.get("harness") not in ("nanocode-openai", "nanocode-anthropic"):
        raise Refused(f"not a funded E3 record: cell {before.get('cell')!r}, harness {before.get('harness')!r}")
    void = before.get("outcome") == "void"
    case = before["case"]
    calls = before["unmetered_calls"]
    execution = execution_of(record_dir, void)
    if execution is None:
        if data_dir != "-":
            raise Refused(f"the void record names no execution, so nothing ran: DATA_DIR is `-`, not {data_dir}")
        spend_text, spend, charges = None, None, 0
    else:
        if data_dir == "-":
            raise Refused(f"the record names execution {execution}: DATA_DIR is its kept data directory, not `-`")
        execs = [line.split()[0] for line in ledger(data_dir, "execs").splitlines()
                 if re.match(r"[0-9A-HJKMNP-TV-Z]{26}\s", line)]
        if execs != [execution]:
            raise Refused(f"{data_dir} holds executions {execs}, not exactly {execution}")
        spend_text = renamed_spend_ledger(ledger(data_dir, "record", execution))
        spend = tomllib.loads(spend_text)
        charges = spend["unknown_charges"]
    if "unknown_charges" in before and before["unknown_charges"] != charges:
        raise Refused(f"the record states unknown_charges {before['unknown_charges']}, ledger.py reads {charges}")
    fill_tokens = void and spend is not None and before["tokens_recorded"] == "unknown"
    if spend is None:
        if calls != 0:
            raise Refused(f"a void naming no execution says unmetered_calls {calls}: nothing ran, so 0")
    elif fill_tokens:
        if calls != 0:
            raise Refused(f"a void record with tokens unknown says unmetered_calls {calls}, not the rig's 0")
    elif void:
        want_counts = (spend["tokens_recorded"], void_calls(case, charges))
        if (before["tokens_recorded"], calls) != want_counts:
            raise Refused(f"a void record's counts {before['tokens_recorded']}, {calls} issued unknown are not "
                          f"ledger.py's {want_counts[0]} and the lower bound {want_counts[1]}")
    else:
        if spend["tokens_recorded"] != before["tokens_recorded"]:
            raise Refused(f"tokens_recorded: the record says {before['tokens_recorded']}, "
                          f"ledger.py reads {spend['tokens_recorded']}")
        problem = counts_problem(case, calls, charges)
        if problem:
            raise Refused(problem)
    if provider:
        tokens_provider, cost_provider = provider
    elif before["credential_mode"] == "subscription":
        tokens_provider, cost_provider = SUBSCRIPTION
    else:
        tokens_provider, cost_provider = API_KEY
    for key in ("tokens_provider", "cost_provider"):
        if before[key] not in (PLACEHOLDER, SUBSCRIPTION[0], SUBSCRIPTION[1], API_KEY[0]) and not provider:
            raise Refused(f"{key} is {before[key]!r}, neither the rig's placeholder nor a ruled value")
    want = dict(before)
    want["tokens_provider"] = tokens_provider
    want["cost_provider"] = cost_provider
    want["unknown_charges"] = charges
    if fill_tokens:
        want["tokens_recorded"] = spend["tokens_recorded"]
        want["unmetered_calls"] = void_calls(case, charges)
    what = spend_ledger_what(void, case)
    new_artifact = spend is not None and not any(a["path"] == "spend-ledger.toml" for a in before["artifacts"])
    if spend is not None:
        want["cost_recorded"] = spend["cost_recorded"]
        want.pop("cost_recorded_usd", None)
        if "cost_recorded_usd" in spend:
            want["cost_recorded_usd"] = spend["cost_recorded_usd"]
        want["artifacts"] = [a for a in before["artifacts"] if a["path"] != "spend-ledger.toml"] + [
            {"path": "spend-ledger.toml", "what": what}]
        with open(os.path.join(record_dir, "spend-ledger.toml"), "w", encoding="utf-8") as fh:
            fh.write(spend_text)
    artifact_block = None
    if new_artifact:
        artifact_block = '[[artifacts]]\npath = "spend-ledger.toml"\nwhat = "' + what + '"\n\n'
    out = []
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    for line in lines:
        key = line.split("=", 1)[0].strip() if "=" in line and not line.startswith("[") else None
        if key == "cost_recorded_usd" and not line.startswith(" "):
            continue
        if fill_tokens and key == "tokens_recorded":
            continue
        if key == "unknown_charges":
            continue
        if key == "unmetered_calls":
            # The rig's toml serializer sorts keys: unknown_charges sorts just before it.
            out.append(toml_line("unknown_charges", charges))
            out.append(toml_line(key, want[key]))
            continue
        if key == "what" and out and out[-1] == 'path = "spend-ledger.toml"\n':
            out.append(toml_line(key, what))
            continue
        if key == "tokens_provider" and provider:
            out.append("tokens_provider = { " + ", ".join(f"{k} = {v}" for k, v in tokens_provider.items()) + " }\n")
            continue
        if key in ("tokens_provider", "cost_provider"):
            out.append(toml_line(key, want[key]))
            continue
        if key == "cost_recorded":
            out.append(toml_line(key, want[key]))
            if "cost_recorded_usd" in want:
                out.append(toml_line("cost_recorded_usd", want["cost_recorded_usd"]))
            continue
        if line.strip() == "[tokens_recorded]" and artifact_block:
            out.append(artifact_block)
            artifact_block = None
        out.append(line)
    # A record with no [tokens_recorded] table (a void's "unknown") ends in its [[artifacts]]:
    # the new artifact, then the filled table, go after them.
    if artifact_block:
        out.append("\n" + artifact_block.rstrip("\n") + "\n")
    if fill_tokens:
        out.append(tokens_table(spend["tokens_recorded"]))
    text = "".join(out)
    after = tomllib.loads(text)
    if after != want:
        diff = sorted(k for k in set(after) | set(want) if after.get(k) != want.get(k))
        raise Refused(f"the rewrite would change more than its fields: {diff}")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return execution, spend, after


def main(argv):
    args = argv[1:]
    provider = None
    if "--provider-tokens" in args or "--provider-cost" in args:
        try:
            i, j = args.index("--provider-tokens"), args.index("--provider-cost")
            counts = [int(x) for x in args[i + 1].split(",")]
            cost = args[j + 1]
        except (ValueError, IndexError):
            sys.stderr.write(__doc__)
            return 2
        if len(counts) != 4 or not re.fullmatch(r"\$[0-9]+(?:\.[0-9]+)?", cost):
            sys.stderr.write(__doc__)
            return 2
        keys = ("input", "cache_read", "cache_write", "output")
        provider = (dict(zip(keys, counts)), cost)
        args = [a for k, a in enumerate(args) if k not in (i, i + 1, j, j + 1)]
    if len(args) != 2:
        sys.stderr.write(__doc__)
        return 2
    try:
        execution, spend, after = finish(args[0], args[1], provider)
    except Refused as e:
        sys.stderr.write(f"e3-finish: refused: {e}\n")
        return 3
    if spend is None:
        print(f"e3-finish: {args[0]}: a void naming no execution; provider fields only")
        return 0
    print(f"e3-finish: {args[0]}: execution {execution}; tokens {spend['tokens_recorded']}; "
          f"unmetered_calls {after['unmetered_calls']}; unknown_charges {after['unknown_charges']}; "
          f"cost_recorded {spend['cost_recorded']}"
          + (f" {spend['cost_recorded_usd']}" if "cost_recorded_usd" in spend else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
