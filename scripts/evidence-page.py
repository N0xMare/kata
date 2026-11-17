#!/usr/bin/env python3
"""Validate the evidence run records and keep docs/evidence/README.md equal to their render.

  check          refuse an invalid run record, or a page whose rendered sections differ
                 from what the records render to (exit 1)
  render         rewrite the page's rendered sections from the records
  --self-test    prove each refusal against a planted record, and the empty-state render

The page claims a run only inside its fenced sections (`<!-- evidence:<section>:begin -->`
… `:end -->`, for E1, E2, E3, E9 and parity), and those sections are a pure function of
the committed records under `docs/evidence/runs/`. So a row with no record behind it, or a
record the page does not show, is a refusal, and with no record every section reads "not
yet run". The prose outside the fences states the rules and the cases; it names no result.

A RECORD is `docs/evidence/runs/<run-id>/run.toml` plus the artifacts beside it. `check`
refuses a record that:
  - is not valid TOML, lacks a field in `FIELDS`, carries a field not in `FIELDS`, or
    holds a value of the wrong type;
  - names a `cell`, `case`, `harness`, `surface`, `credential_mode`, `capsule_network` or
    `outcome` outside its enumeration (`CASES`, `HARNESSES`, …); `HARNESSES` are the four
    harnesses of the two declared `PAIRS`, so a harness outside them is refused;
  - states a `model` or `effort` other than its harness's pair's (`PAIRS`: the OpenAI pair,
    `codex-stock` vs `nanocode-openai`, on gpt-6-luna / medium; the Anthropic pair,
    `claude-agent-acp` vs `nanocode-anthropic`, on claude-sonnet-5-5 / medium);
  - runs a cell on a harness `CELL_HARNESSES` does not list for it (E3 and E9 run on
    `nanocode-openai` and `nanocode-anthropic` only);
  - is an E3 run that states no observed `settlement` (one of `SETTLEMENTS`), or a run of
    another cell that states one; passes (`outcome = "pass"`) with a settlement other than
    its case's `EXPECTED_SETTLEMENT`; states `other` without a `settlement_detail` naming
    what was observed, or a detail with any other settlement;
  - is an E2 `pr` or `refine` run that does not state the observed fields the kit's
    observed.toml holds, `variant` (one of `VARIANTS`, on every outcome) and `refined` (one
    of `REFINED`, on every outcome but `void`: a void run may have no observed.toml; one it
    states is still enumerated), or a run of any other cell or case that states either; is a `pr` run whose
    variant is not `task-only` or `refine-addendum`, or a `refine` run whose variant is not
    `refine-cell` (`CASE_VARIANTS`); is a `refine` pass with `refined` other than `yes`.
    A `pr` run's `refined` constrains nothing: a pass that did not refine is valid;
  - is a non-void run of a cell and case a kit writes oracles.txt for (`ORACLE_COUNTS`:
    E1 `seeded-pr` and `public-pr`, E2 `pr` and `refine`) whose `outcome_source` does not
    start `oracles.txt:`, or a non-void E2 `pr` or `refine` run that does not list
    `kit-sha256.txt`;
  - is a non-void run, of any cell, whose `outcome_source` starts `oracles.txt:` and whose
    cell and case no kit writes oracles.txt for (`ORACLE_COUNTS`: E1 `seeded-pr` and
    `public-pr`, e1-run.sh's 8; E2 `pr` and `refine`, e2-oracles.sh's 10 and 18), or whose
    oracles.txt is not UTF-8, has a line that is not `PASS <oracle>` or `FAIL
    <oracle>[: <detail>]` (only a FAIL line carries a detail; no line holds a carriage
    return, so CRLF and CR-separated files are refused), holds other than its
    `ORACLE_COUNTS` lines, does not end with its `LAST_ORACLE` where the kit names one
    (`kit-intact`, E2 only), or holds a FAIL line on a pass or none on a fail (only the
    count, the shape and the last name: not which oracles);
  - is an E2 run, of any case, that lists an artifact whose file name, at any depth, is
    `<harness>.json`, the name of the refine cell's params file, which holds the held-out
    gate (a renamed copy is not refused);
  - submits through `rest` or `mcp` without saying how it authenticated (`api_auth`, one of
    `API_AUTH`), or states `api_auth` for a `cli` run;
  - states a capsule network its harness does not have (a nanocode capsule is `offline`,
    a baseline's — `codex-stock`, `claude-agent-acp` — `vendor-egress-only`);
  - records a priced cost under a subscription login (`credential_mode = "subscription"`
    requires `cost_recorded = "unavailable"`), or for a harness kata prices no turn of
    under any login (every harness but `PRICED`, `codex-stock` and `nanocode-anthropic`:
    `AdapterKind::billing_backend` is Some only for nanocode_anthropic, and was for
    codex_app_server in every build a committed codex-stock record names), or a priced cost
    with no `cost_recorded_usd`;
  - gives `kata_sha`, `kata_tree` or `nanocode_rev` as anything but 40 lowercase hex, or
    `started_utc` as anything but `YYYY-MM-DDTHH:MM:SSZ`;
  - is a baseline run (`codex-stock`, `claude-agent-acp`) whose `kata_sha` is not
    `RETIRED_BASELINE_SHA`, the counted round's pinned commit: no later build carries a
    baseline's adapter;
  - is a nanocode run without `nanocode_rev`; is a baseline run without a
    `vendor_version` that is its vendor's `--version` line (`VENDOR_VERSION`: `codex-cli
    <version>` on `codex-stock`, the bare `<version>` on `claude-agent-acp`), or a nanocode
    run that states one (`nanocode_rev` is optional on a baseline);
  - passes with `tokens_recorded = "unknown"` (a pass reads kata's counts from the
    database), or states a negative `unmetered_calls` (every record, of every cell, counts
    unknown usage there, beside the known part in `tokens_recorded`; a pass with some is
    valid). Its unit is the cell's reader's: on E1, E2 and E9 the kit copies ledger.py
    `record`'s count, which is unknown CHARGES (one per attempt kata could not meter); on E3
    the rig's, the ISSUED model calls whose usage is unknown;
  - is an E3 record without `unknown_charges` (ledger.py's charges, which e3-finish.py
    writes; an unfinished record has none), or with a negative one, or a record of another
    cell with one; or an E3 record whose two counts `e3_counts_problem` refuses: on P1 and
    P1-host (whose killed attempt is never sent) any issued call of unknown usage; in every
    other case issued calls with no unknown charge, or fewer issued calls than charges;
  - is `void` without a `void_reason` that starts `<a listed artifact's path>:` (the
    positive control or the infrastructure that failed, read from an artifact: a void run
    is not a harness outcome), or states a `void_reason` and is not `void`;
  - gives token counts that are not a table of the four non-negative integers `input`,
    `cache_read`, `cache_write`, `output` (or, for the recorded side, `"unknown"`; for the
    provider side, a string starting `unavailable: ` with a non-blank reason), or a
    `cost_provider` that is neither `unavailable: <reason>` (non-blank) nor the provider's
    figure, `$<amount>` (`PROVIDER_COST`); only the shape: which reason, and whether a
    figure was read for the run alone, are not checked;
  - lives in a directory whose name is not `<cell>-<case>-<harness>-<started, compact>`
    (`e1-seeded-pr-nanocode-openai-20261101T120000Z`);
  - lists an artifact that is absent, absolute, or outside its directory, or leaves a file
    in its directory unlisted;
  - is, or holds, a symbolic link anywhere in its directory (a link's target is not the
    committed content);
  - has an `outcome_source` that does not start with `<a listed artifact's path>:` (the
    outcome must be read from an artifact holding what git, the forge, the remote or a
    read-only database said, not from kata's own report).
Across records, `check` refuses a COUNTED ROUND (`round_problems`) whose E1/E2 parity-case
runs and E2 `refine` runs (`ROUND_KEYS`, any outcome, both pairs) carry more than one
`kata_sha`, or in which an
E1 case's counted runs on a harness (the first `PARITY_RUNS` non-void, by `started_utc`)
include a run submitted through a surface outside `E1_SURFACES` (`cli`, `rest`), or lack
one of them once no later run can supply it (a later run never replaces a counted one), or
whose counted E2 `pr` runs (the first `PARITY_RUNS` non-void on each harness, both pairs)
differ in `variant`; `refined` is never compared, and the variant of a void run, or of a
run after the first `PARITY_RUNS`, is outside that rule. The order of the surfaces (run 1
CLI, run 2 REST, run 3 either) and replacing a void run on its own surface are the
procedure the runs follow to keep that mix, not refusals: a counted set in another order
that still holds both is accepted. E2's `refine` is in the round only for its one
`kata_sha`; E2's `mismatch`, E3 and E9 are outside it, and the round has no notion of
an uncounted run: a validation run is not committed under `RUNS`.
In THE ARCHIVE — a git work tree rooted at `ROOT` whose HEAD descends from `ARCHIVE_ROOT`,
the root commit of kata's private history — `check` also refuses a record whose `kata_sha`
is not a commit that is an ancestor of HEAD, or whose `kata_tree` is not that commit's
tree. Anywhere else (the public repository, one squashed commit with no such root; a
tarball; a shallow clone that lacks the root) only their shape is checked, because the
chain they name is not there to read.
THE KIT (`kit_problems`): every regular file directly under `KIT` (`scripts/evidence-kit/`)
is committed as the bytes the records ran, so `check` refuses a record that lists
`kit-sha256.txt` (the kit snapshot's manifest, `<sha256>  ./<path>` per line) and does
not pin each of those files there, by its name, at the committed file's sha256. Only the
committed files are compared: the manifest's other lines (the held-out oracles and gate,
the task texts) are not, and a record that lists no manifest (E1, or a void E2 run; a
non-void E2 `pr` or `refine` run must list one) is not read.

PARITY is computed and rendered per pair, over that pair's two harnesses only: per E1 and
E2 case that `PARITY_CASES` counts, the first `PARITY_RUNS` non-void runs on each harness
by `started_utc`. A pair reads "met" only when every case has that many counted runs on
both its harnesses and in every case the pair's nanocode harness passes at least as many
counted runs as its baseline; otherwise it names the first rule that failed. Each cell
also shows the void runs it skipped. (One model and effort per pair, one `kata_sha` per
round, the E1 surface mix and one E2 variant are refusals, above.)

The E2 table shows each run's `variant` and `refined`, and a `refine` row whose cell per
harness is its first `REFINE_RUNS` non-void refine run by `started_utc` (its outcome and
`refined`, with the runs it did not count and the void ones beside it), or "not yet run".

The artifacts' content is `scripts/evidence-sanitize.py`'s to refuse (`docs/evidence/**`
is in its scanned set); this script reads none of it but a run's oracles.txt.

WHAT A PASS DOES NOT MEAN: it does not re-run anything or re-read any oracle. It proves the
page shows exactly the committed records, and that each record is complete and internally
consistent; whether an artifact really holds what `outcome_source` says is for the reader
to check, which is why every artifact is linked.
"""

import argparse
import hashlib
import os
import re
import sys
import tempfile
import tomllib
from collections import namedtuple

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
PAGE = "docs/evidence/README.md"
RUNS = "docs/evidence/runs"

CELLS = ("E1", "E2", "E3", "E9")
CASES = {
    "E1": ("seeded-pr", "public-pr"),
    "E2": ("pr", "mismatch", "refine"),
    "E3": (
        "gate-main-kill",
        "gate-worker-kill",
        "P1",
        "P2",
        "P3",
        "P4",
        "P1-host",
        "P2-host",
        "P3-host",
        "P4-host",
    ),
    "E9": ("clean-vm",),
}
# E3's observed settlement classes (D2 §5.4); `other` carries a `settlement_detail`.
SETTLEMENTS = ("resumed-at-gate", "proven-ambiguous", "pr-opened-once", "other")
EXPECTED_SETTLEMENT = {
    "gate-main-kill": "resumed-at-gate",
    "gate-worker-kill": "resumed-at-gate",
    "P1": "proven-ambiguous",
    "P2": "proven-ambiguous",
    "P3": "proven-ambiguous",
    "P4": "pr-opened-once",
    "P1-host": "proven-ambiguous",
    "P2-host": "proven-ambiguous",
    "P3-host": "proven-ambiguous",
    "P4-host": "pr-opened-once",
}
# E2's task variants (the kit's RUNBOOK §4, §4b): a `pr` run's task is task.md alone or
# with the refine addendum; the refine cell's is task.md + refine-cell.md.
VARIANTS = ("task-only", "refine-addendum", "refine-cell")
CASE_VARIANTS = {"pr": ("task-only", "refine-addendum"), "refine": ("refine-cell",)}
# Whether the run's fix loop refined (`test#iter-0` failed and a later iteration ran), as
# the kit's observed.toml states it: observed on a `pr` run, required of a refine pass.
REFINED = ("yes", "no")
# The refine runs the E2 table shows per harness: the first REFINE_RUNS non-void by
# `started_utc` (the cell is never re-run to fish for a refine).
REFINE_RUNS = 1
# The oracle lines a kit writes to oracles.txt per cell and case it judges: e1-run.sh's
# eight for either E1 case; e2-oracles.sh's ten for a `pr` run and eighteen for a `refine`
# run (the refine cell's eight on top of a `pr` run's ten). A run of any other cell or case
# has no oracles.txt to read its outcome from.
ORACLE_COUNTS = {("E1", "seeded-pr"): 8, ("E1", "public-pr"): 8, ("E2", "pr"): 10, ("E2", "refine"): 18}
# The oracle a kit writes last, where it states one: e2-oracles.sh's `kit-intact`.
LAST_ORACLE = {("E2", "pr"): "kit-intact", ("E2", "refine"): "kit-intact"}
# `PASS <oracle>`, or `FAIL <oracle>` with an optional `: <detail>`; no carriage return.
ORACLE_LINE = re.compile(r"PASS (?P<pass>[a-z0-9][a-z0-9-]*)|FAIL (?P<fail>[a-z0-9][a-z0-9-]*)(?:: [^\r]*)?")


class Pair(namedtuple("Pair", "name baseline nanocode model effort")):
    """A parity pair: a stock vendor harness (the baseline) beside kata's embedded nanocode
    harness for the same provider, both pinned to one model and reasoning effort."""


# The declared pairs (owner 2026-10-31: 4c and 13:20 #3). Every record's harness is in one,
# and its model and effort are that pair's; parity compares only within a pair.
PAIRS = (
    Pair("OpenAI", "codex-stock", "nanocode-openai", "gpt-6-luna", "medium"),
    Pair("Anthropic", "claude-agent-acp", "nanocode-anthropic", "claude-sonnet-5-5", "medium"),
)
PAIR_OF = {h: p for p in PAIRS for h in (p.baseline, p.nanocode)}
HARNESSES = tuple(PAIR_OF)
NANOCODE = tuple(p.nanocode for p in PAIRS)
BASELINES = tuple(p.baseline for p in PAIRS)
# The harnesses each cell runs on: E1 and E2 on both pairs; E3 and E9 on either nanocode
# harness (D2 §5.4's matrix with its anthropic arm; E9's guest logs in either way).
CELL_HARNESSES = {"E1": HARNESSES, "E2": HARNESSES, "E3": NANOCODE, "E9": NANOCODE}
# A nanocode capsule is offline (its model traffic leaves from the worker); a stock vendor's
# capsule reaches its vendor's endpoints.
CAPSULE_NETWORK = {h: "offline" if h in NANOCODE else "vendor-egress-only" for h in HARNESSES}
# The harnesses kata prices a turn of: `AdapterKind::billing_backend` is Some only for
# nanocode_anthropic, and only under an API key (a subscription call is never priced).
# The vendor baselines are HISTORICAL: this build carries no adapter for codex-stock
# (codex_app_server) or claude-agent-acp (generic_acp), and their committed records were
# judged by the build each names in `kata_sha`, which priced codex_app_server and not the
# generic ACP client — `HISTORICAL_PRICED`. The self-test reads `billing_backend` out of
# `AGENT_RS` and refuses a PRICED whose current harnesses differ from it, so a pricing
# change in the engine reds `just evidence-check` until this, the README's Spend rule and
# the priced-* cells move with it.
HISTORICAL_PRICED = ("codex-stock",)
# The build every baseline record ran on: the counted round's one pinned commit
# (34d5c77c8ff7). No later build carries a baseline's adapter, so a baseline record
# naming any other `kata_sha` is refused.
RETIRED_BASELINE_SHA = "34d5c77c8ff7b1e521f67b9d7ecb2bddd16e6790"
PRICED = HISTORICAL_PRICED + ("nanocode-anthropic",)
# The `AdapterKind` each harness this build carries runs as.
ADAPTER_KIND = {
    "nanocode-openai": "NanocodeOpenai",
    "nanocode-anthropic": "NanocodeAnthropic",
}
AGENT_RS = "crates/types/src/agent.rs"
SURFACES = ("cli", "rest", "mcp")
# How an API-surface run authenticated: a minted signed token, or none because the node
# runs with loopback API auth disabled. A CLI run states none.
API_AUTH = ("signed-token", "loopback-disabled")
CREDENTIAL_MODES = ("subscription", "api_key")
OUTCOMES = ("pass", "fail", "void")
COST_RECORDED = ("unavailable", "estimated")
TOKEN_KEYS = ("input", "cache_read", "cache_write", "output")
# The parity rule counts these cases (E2's mismatch cell is a refusal, not an implement run).
PARITY_CASES = {"E1": ("seeded-pr", "public-pr"), "E2": ("pr",)}
PARITY_KEYS = tuple((cell, case) for cell, cases in PARITY_CASES.items() for case in cases)
# The (cell, case) pairs the counted round runs on its one pinned commit: the parity cases
# and E2's refine cell, which runs in the same round but is no parity case.
ROUND_KEYS = (*PARITY_KEYS, ("E2", "refine"))
# The non-void runs parity counts per case per harness: the first PARITY_RUNS by
# `started_utc`. The count is the owner's decision (docs/evidence/README.md, Parity).
PARITY_RUNS = 3
# The surfaces each E1 case's counted runs include on each harness.
E1_SURFACES = ("cli", "rest")
# The root commit of kata's private history (the archive). Where it is an ancestor of HEAD,
# the full chain is present and `kata_sha` must be reachable from HEAD.
ARCHIVE_ROOT = "f9505bc18941a8c7105d7088c90275cec18968d9"
# A release version, MAJOR.MINOR.PATCH with an optional pre-release or build suffix.
_SEMVER = r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.\-]+)?"
# A baseline's `vendor_version`: the line its vendor's `--version` prints inside the bound
# environment, as (command, line pattern, the line's shape). `codex --version` prints
# `codex-cli <version>`; `claude-agent-acp --version` prints the bare version (0.79.0).
VENDOR_VERSION = {
    "codex-stock": ("codex", re.compile("codex-cli " + _SEMVER), "codex-cli <version>"),
    "claude-agent-acp": ("claude-agent-acp", re.compile(_SEMVER), "<version>"),
}

# name -> (type, required)
FIELDS = {
    "cell": (str, True),
    "case": (str, True),
    "harness": (str, True),
    "surface": (str, True),
    "api_auth": (str, False),
    "kata_sha": (str, True),
    "kata_tree": (str, True),
    "nanocode_rev": (str, False),
    "vendor_version": (str, False),
    "model": (str, True),
    "effort": (str, True),
    "credential_mode": (str, True),
    "capsule_network": (str, True),
    "started_utc": (str, True),
    "wall_seconds": (int, True),
    "outcome": (str, True),
    "outcome_source": (str, True),
    "void_reason": (str, False),
    "settlement": (str, False),
    "settlement_detail": (str, False),
    "variant": (str, False),
    "refined": (str, False),
    "tokens_recorded": ((dict, str), True),
    "tokens_provider": ((dict, str), True),
    "unmetered_calls": (int, True),
    "unknown_charges": (int, False),
    "cost_recorded": (str, True),
    "cost_recorded_usd": (float, False),
    "cost_provider": (str, True),
    "artifacts": (list, True),
}

HEX40 = re.compile(r"[0-9a-f]{40}")
# The provider's own dollar figure for a run, as `cost_provider` states it.
PROVIDER_COST = re.compile(r"\$[0-9]+(?:\.[0-9]+)?")
STARTED = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z")


class Record:
    def __init__(self, run_id, data):
        self.run_id = run_id
        self.d = data

    def __getattr__(self, name):
        return self.d.get(name)


def _unavailable(value):
    """A provider-side `unavailable: <reason>`, with a reason that is not blank."""
    return value.startswith("unavailable: ") and bool(value[13:].strip())


def _tokens_problem(value, side):
    if isinstance(value, str):
        if side == "recorded" and value == "unknown":
            return None
        if side == "provider" and _unavailable(value):
            return None
        want = '"unknown"' if side == "recorded" else '"unavailable: <reason>"'
        return f"tokens_{side} string must be {want}"
    if set(value) != set(TOKEN_KEYS):
        return f"tokens_{side} keys must be exactly {', '.join(TOKEN_KEYS)}"
    for k in TOKEN_KEYS:
        v = value[k]
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            return f"tokens_{side}.{k} must be a non-negative integer"
    return None


# The E3 cases whose killed attempt is placed and never sent: it issued no model call, and
# its unknown charges may be any number (zero model calls for that attempt).
UNSENT_CASES = ("P1", "P1-host")


def e3_counts_problem(case, calls, charges):
    """Why an E3 record's `calls` issued calls of unknown usage (`unmetered_calls`) cannot
    stand beside its `charges` unknown charges (`unknown_charges`), or None. The refused set:
      - in UNSENT_CASES, every pair with calls != 0 (charges >= 0 is any): the killed
        attempt was never sent, so it issued no call;
      - in every other case, calls > 0 beside charges == 0 (a call is inside an attempt, and
        an attempt with a call kata did not meter is an unknown charge), and calls < charges
        (each killed attempt was sent, so each unknown charge issued at least one call; 0
        calls beside a charge included). One killed attempt is one charge however many calls
        it issued, so no upper bound holds.
    The same rule as e3-finish.py's `counts_problem`."""
    if case in UNSENT_CASES:
        if calls != 0:
            return (f"{calls} issued call(s) of unknown usage on {case}, whose killed attempt is never sent: "
                    "0 issued calls, beside any `unknown_charges`")
        return None
    if calls > 0 and charges == 0:
        return f"{calls} issued call(s) of unknown usage beside 0 `unknown_charges`"
    if calls < charges:
        return (f"{calls} issued call(s) of unknown usage, fewer than its {charges} `unknown_charges`: outside "
                f"{' and '.join(UNSENT_CASES)} each unknown charge issued at least one call")
    return None


def _charges_problems(run_id, d):
    if d["cell"] != "E3":
        if "unknown_charges" in d:
            why = "another cell's `unmetered_calls` is already ledger.py's unknown charges"
            return [f"{run_id}: only an E3 record states `unknown_charges`: {why}"]
        return []
    if "unknown_charges" not in d:
        return [f"{run_id}: an E3 record states `unknown_charges`, ledger.py's count, which e3-finish.py writes"]
    if d["unknown_charges"] < 0:
        return [f"{run_id}: `unknown_charges` is negative"]
    problem = e3_counts_problem(d["case"], d["unmetered_calls"], d["unknown_charges"])
    return [f"{run_id}: {problem}"] if problem else []


def _settlement_problems(run_id, d):
    if d["cell"] != "E3":
        return [f"{run_id}: only an E3 run states `{k}`" for k in ("settlement", "settlement_detail") if k in d]
    settlement = d.get("settlement")
    if settlement not in SETTLEMENTS:
        return [f"{run_id}: an E3 run states its observed `settlement`, one of {', '.join(SETTLEMENTS)}"]
    problems = []
    expected = EXPECTED_SETTLEMENT.get(d["case"])
    if d["outcome"] == "pass" and expected and settlement != expected:
        problems.append(f"{run_id}: a {d['case']} pass settles {expected}, not {settlement}")
    if (settlement == "other") != bool(d.get("settlement_detail", "").strip()):
        problems.append(f"{run_id}: `settlement_detail` is stated exactly when the settlement is other")
    return problems


def _observed_problems(run_id, d):
    """`variant` and `refined`: stated only on an E2 pr or refine run, each in its
    enumeration; `variant` on every such run, `refined` on every one but a void run (whose
    kit may have stopped before observed.toml was written); a pr run's variant is
    task-only or refine-addendum, a refine run's refine-cell; a refine pass refined. A pr
    run's `refined` constrains nothing."""
    if d["cell"] != "E2" or d["case"] not in CASE_VARIANTS:
        return [f"{run_id}: only an E2 pr or refine run states `{k}`" for k in ("variant", "refined") if k in d]
    case = d["case"]
    required = ("variant",) if d["outcome"] == "void" else ("variant", "refined")
    missing = [k for k in required if k not in d]
    if missing:
        return [f"{run_id}: an E2 {case} run states `{k}`, copied from the kit's observed.toml" for k in missing]
    problems = []
    if d["variant"] not in VARIANTS:
        problems.append(f"{run_id}: `variant` = {d['variant']!r} is not one of {', '.join(VARIANTS)}")
    elif d["variant"] not in CASE_VARIANTS[case]:
        problems.append(f"{run_id}: an E2 {case} run's variant is {' or '.join(CASE_VARIANTS[case])}, not {d['variant']!r}")
    if "refined" not in d:
        return problems
    if d["refined"] not in REFINED:
        problems.append(f"{run_id}: `refined` = {d['refined']!r} is not one of {', '.join(REFINED)}")
    elif case == "refine" and d["outcome"] == "pass" and d["refined"] != "yes":
        problems.append(f"{run_id}: a refine pass states `refined = \"yes\"`: the cell passes only when its loop refined")
    return problems


def _oracles_problems(run_id, run_dir, d):
    """A non-void run whose outcome_source reads `oracles.txt:` is judged by the kit's
    oracles.txt: one `PASS <oracle>` or `FAIL <oracle>[: <detail>]` line per oracle
    (ORACLE_LINE: no carriage return), ORACLE_COUNTS of them for its cell and case, its
    LAST_ORACLE last where the kit names one, and `pass` exactly when every line passes."""
    cell, case = d["cell"], d["case"]
    want = ORACLE_COUNTS.get((cell, case))
    if want is None:
        return [f"{run_id}: no kit judges an {cell} {case} run by oracles.txt (ORACLE_COUNTS)"]
    path = os.path.join(run_dir, "oracles.txt")
    if os.path.islink(path) or not os.path.isfile(path):
        return []  # the artifact refusals name it
    try:
        with open(path, encoding="utf-8", newline="") as fh:  # no newline translation
            lines = fh.read().split("\n")
    except UnicodeDecodeError:
        return [f"{run_id}: oracles.txt is not UTF-8 text"]
    if lines[-1] == "":
        lines.pop()
    oracles = []
    for i, line in enumerate(lines, 1):
        m = ORACLE_LINE.fullmatch(line)
        if not m:
            return [f"{run_id}: oracles.txt line {i} is not `PASS <oracle>` or `FAIL <oracle>[: <detail>]`"]
        oracles.append((m["pass"] or m["fail"], m["fail"] is not None))
    problems = []
    last = LAST_ORACLE.get((cell, case))
    if len(oracles) != want:
        problems.append(f"{run_id}: oracles.txt holds {len(oracles)} oracle(s); an {cell} {case} run is judged by {want}")
    elif last is not None and oracles[-1][0] != last:
        problems.append(f"{run_id}: the last oracle in oracles.txt is `{last}`")
    fails = sum(failed for _, failed in oracles)
    if (d["outcome"] == "pass") != (fails == 0):
        problems.append(
            f"{run_id}: outcome {d['outcome']!r} with {fails} FAIL line(s) in oracles.txt; a run passes exactly when "
            "every oracle passes"
        )
    return problems


def priced_adapter_kinds(source):
    """The `AdapterKind` variants `billing_backend` answers Some for, read from its source:
    a `match self` whose every arm is `Self::A | Self::B => Some(..)` or `_ => None`. None
    when the function has any other shape, which the self-test refuses as unreadable."""
    m = re.search(
        r"pub const fn billing_backend\(self\) -> Option<BillingBackend> \{\s*match self \{\n(.*?)\n\s*\}\n\s*\}",
        source,
        re.S,
    )
    if not m:
        return None
    priced = set()
    for line in m.group(1).splitlines():
        arm = re.fullmatch(r"\s*((?:Self::\w+\s*\|\s*)*Self::\w+|_)\s*=>\s*(Some\(BillingBackend::\w+\)|None),", line)
        if not arm or (arm[1] == "_" and arm[2] != "None"):
            return None
        if arm[2] != "None":
            priced |= {k.strip().removeprefix("Self::") for k in arm[1].split("|")}
    return priced


def expected_run_id(d):
    m = STARTED.fullmatch(d["started_utc"])
    compact = "".join(m.groups()[:3]) + "T" + "".join(m.groups()[3:]) + "Z"
    return f"{d['cell'].lower()}-{d['case']}-{d['harness']}-{compact}"


def validate(run_dir):
    """Return (record or None, [problem]) for one run directory."""
    run_id = os.path.basename(run_dir.rstrip("/"))
    problems = []
    path = os.path.join(run_dir, "run.toml")
    if os.path.islink(run_dir.rstrip("/")) or os.path.islink(path):
        return None, [f"{run_id}: the run directory or its run.toml is a symbolic link"]
    try:
        with open(path, "rb") as fh:
            d = tomllib.load(fh)
    except FileNotFoundError:
        return None, [f"{run_id}: no run.toml"]
    except tomllib.TOMLDecodeError as err:
        return None, [f"{run_id}: run.toml is not valid TOML: {err}"]

    for name, (typ, required) in FIELDS.items():
        if name not in d:
            if required:
                problems.append(f"{run_id}: missing field `{name}`")
            continue
        v = d[name]
        if isinstance(v, bool) or not isinstance(v, typ):
            problems.append(f"{run_id}: field `{name}` has the wrong type")
    for name in d:
        if name not in FIELDS:
            problems.append(f"{run_id}: unknown field `{name}`")
    if problems:
        return None, problems

    enums = (
        ("cell", CELLS),
        ("harness", HARNESSES),
        ("surface", SURFACES),
        ("credential_mode", CREDENTIAL_MODES),
        ("outcome", OUTCOMES),
        ("cost_recorded", COST_RECORDED),
    )
    for name, allowed in enums:
        if d[name] not in allowed:
            problems.append(f"{run_id}: `{name}` = {d[name]!r} is not one of {', '.join(allowed)}")
    if d["cell"] in CASES and d["case"] not in CASES[d["cell"]]:
        problems.append(f"{run_id}: `case` = {d['case']!r} is not a case of {d['cell']}")
    if d["surface"] in ("rest", "mcp") and d.get("api_auth") not in API_AUTH:
        problems.append(f"{run_id}: a {d['surface']} run states api_auth, one of {', '.join(API_AUTH)}")
    if d["surface"] == "cli" and "api_auth" in d:
        problems.append(f"{run_id}: a cli run states no api_auth")
    allowed = CELL_HARNESSES.get(d["cell"], HARNESSES)
    if d["harness"] in HARNESSES and d["harness"] not in allowed:
        problems.append(f"{run_id}: {d['cell']} runs on {', '.join(allowed)} only")
    pair = PAIR_OF.get(d["harness"])
    for name in ("model", "effort") if pair else ():
        if d[name] != getattr(pair, name):
            problems.append(
                f"{run_id}: a {d['harness']} run is in the {pair.name} pair, whose {name} is "
                f"{getattr(pair, name)}, not {d[name]!r}"
            )
    problems += _settlement_problems(run_id, d)
    problems += _observed_problems(run_id, d)
    want_net = CAPSULE_NETWORK.get(d["harness"])
    if want_net and d["capsule_network"] != want_net:
        problems.append(f"{run_id}: a {d['harness']} capsule is {want_net}, not {d['capsule_network']!r}")
    if d["credential_mode"] == "subscription" and d["cost_recorded"] != "unavailable":
        problems.append(f"{run_id}: a subscription login meters no price; cost_recorded must be unavailable")
    if d["harness"] in HARNESSES and d["harness"] not in PRICED and d["cost_recorded"] != "unavailable":
        problems.append(
            f"{run_id}: kata prices no {d['harness']} turn (AdapterKind::billing_backend is Some only for "
            "nanocode_anthropic, and was for codex_app_server); cost_recorded must be unavailable"
        )
    if d["cost_recorded"] == "estimated" and "cost_recorded_usd" not in d:
        problems.append(f"{run_id}: an estimated cost needs cost_recorded_usd")
    if d["cost_recorded"] == "unavailable" and "cost_recorded_usd" in d:
        problems.append(f"{run_id}: cost_recorded_usd with an unavailable cost")
    for name in ("kata_sha", "kata_tree", "nanocode_rev"):
        if name in d and not HEX40.fullmatch(d[name]):
            problems.append(f"{run_id}: `{name}` must be 40 lowercase hex")
    if d["harness"] in BASELINES and d["kata_sha"] != RETIRED_BASELINE_SHA:
        problems.append(
            f"{run_id}: {d['harness']} is a retired baseline: no build after the counted round "
            f"carries its adapter, so its records are that round's, at `kata_sha` {RETIRED_BASELINE_SHA}"
        )
    if d["harness"] in NANOCODE and "nanocode_rev" not in d:
        problems.append(f"{run_id}: a {d['harness']} run states `nanocode_rev`, the nanocode revision kata pins")
    vendor = VENDOR_VERSION.get(d["harness"])
    if vendor and not vendor[1].fullmatch(d.get("vendor_version", "")):
        problems.append(
            f"{run_id}: a {d['harness']} run states `vendor_version`, the `{vendor[0]} --version` line read "
            f"inside the bound environment (`{vendor[2]}`)"
        )
    if not vendor and "vendor_version" in d:
        problems.append(f"{run_id}: only a {' or '.join(VENDOR_VERSION)} run states `vendor_version`")
    if d["outcome"] == "pass" and d["tokens_recorded"] == "unknown":
        problems.append(f"{run_id}: a pass states kata's token counts, read from the database, not \"unknown\"")
    if not STARTED.fullmatch(d["started_utc"]):
        problems.append(f"{run_id}: `started_utc` must be YYYY-MM-DDTHH:MM:SSZ")
    if d["wall_seconds"] < 0:
        problems.append(f"{run_id}: `wall_seconds` is negative")
    if d["unmetered_calls"] < 0:
        problems.append(f"{run_id}: `unmetered_calls` is negative")
    else:
        problems += _charges_problems(run_id, d)
    for side in ("recorded", "provider"):
        p = _tokens_problem(d[f"tokens_{side}"], side)
        if p:
            problems.append(f"{run_id}: {p}")
    cost_provider = d["cost_provider"]
    if not _unavailable(cost_provider) and not PROVIDER_COST.fullmatch(cost_provider):
        problems.append(f"{run_id}: `cost_provider` must be \"unavailable: <reason>\" or the provider's figure, `$<amount>`")
    for name in ("model", "effort", "outcome_source"):
        if not d[name].strip():
            problems.append(f"{run_id}: `{name}` is empty")

    if not problems:
        want = expected_run_id(d)
        if run_id != want:
            problems.append(f"{run_id}: the directory must be named {want}")

    listed = []
    named = []
    for i, a in enumerate(d["artifacts"]):
        if not isinstance(a, dict) or set(a) != {"path", "what"} or not all(isinstance(v, str) for v in a.values()):
            problems.append(f"{run_id}: artifacts[{i}] must be {{ path, what }} strings")
            continue
        rel = a["path"]
        norm = os.path.normpath(rel)
        if os.path.isabs(rel) or norm.startswith("..") or norm == "run.toml":
            problems.append(f"{run_id}: artifact {rel!r} is outside the run directory")
            continue
        full = os.path.join(run_dir, norm)
        if os.path.islink(full):
            problems.append(f"{run_id}: artifact {rel!r} is a symbolic link")
        elif not os.path.isfile(full):
            problems.append(f"{run_id}: artifact {rel!r} is absent")
        listed.append(norm)
        named.append(rel)
    if not listed:
        problems.append(f"{run_id}: no artifact listed")
    present = []
    for dirpath, dirs, files in os.walk(run_dir):
        for f in dirs + files:
            full = os.path.join(dirpath, f)
            rel = os.path.normpath(os.path.relpath(full, run_dir))
            if os.path.islink(full):
                if rel not in listed:
                    problems.append(f"{run_id}: {rel!r} is a symbolic link")
            elif f in files and rel != "run.toml":
                present.append(rel)
    for rel in sorted(set(present) - set(listed)):
        problems.append(f"{run_id}: file {rel!r} is not listed as an artifact")
    if named and not any(d["outcome_source"].startswith(rel + ":") for rel in named):
        problems.append(f"{run_id}: outcome_source must start with `<artifact path>:`, naming the artifact it was read from")
    if d["outcome"] == "void" and not any(d.get("void_reason", "").startswith(rel + ":") for rel in named):
        problems.append(
            f"{run_id}: a void run states `void_reason`, starting `<artifact path>:` with the positive "
            "control that did not hold"
        )
    if d["outcome"] != "void" and "void_reason" in d:
        problems.append(f"{run_id}: only a void run states `void_reason`")
    if d["cell"] == "E2":
        # The refine cell's params file, `~/ke/refine-params/<harness>.json`, holds the
        # held-out gate; it stays outside the run directory. Only its NAME is refused here.
        params = {f"{h}.json" for h in HARNESSES}
        for rel in named:
            if os.path.basename(rel) in params:
                problems.append(
                    f"{run_id}: artifact {rel!r} is named as the refine cell's params file, which holds the "
                    "held-out gate and is never committed"
                )
    if d["outcome"] != "void":
        if (d["cell"], d["case"]) in ORACLE_COUNTS and not d["outcome_source"].startswith("oracles.txt:"):
            problems.append(
                f"{run_id}: an {d['cell']} {d['case']} run's outcome_source is `oracles.txt: ...`, the kit's oracle lines"
            )
        elif d["outcome_source"].startswith("oracles.txt:"):
            problems += _oracles_problems(run_id, run_dir, d)
        if d["cell"] == "E2" and d["case"] in ("pr", "refine") and KIT_MANIFEST not in named:
            problems.append(f"{run_id}: an E2 {d['case']} run lists {KIT_MANIFEST}, the manifest of the kit it judged from")
    return (None if problems else Record(run_id, d)), problems


def _in_archive(root, archive_root):
    """True when `root` is the top of a git work tree whose HEAD descends from `archive_root`."""
    top = _git_out(root, "rev-parse", "--show-toplevel")
    if top is None or os.path.realpath(top) != os.path.realpath(root):
        return False
    return _git_out(root, "merge-base", "--is-ancestor", archive_root, "HEAD") is not None


def _git_out(root, *args):
    """git's stdout, or None when it exits non-zero (or git is absent)."""
    import subprocess

    try:
        done = subprocess.run(["git", "-C", root, *args], capture_output=True, text=True)
    except OSError:
        return None
    return done.stdout.strip() if done.returncode == 0 else None


def provenance_problems(root, records, archive_root):
    """In the archive, each record's `kata_sha` is an ancestor of HEAD and `kata_tree` its tree."""
    if not records or not _in_archive(root, archive_root):
        return []
    problems = []
    for r in records:
        if _git_out(root, "merge-base", "--is-ancestor", f"{r.kata_sha}^{{commit}}", "HEAD") is None:
            problems.append(f"{r.run_id}: `kata_sha` {r.kata_sha} is not an ancestor of HEAD in the archive")
        elif _git_out(root, "rev-parse", f"{r.kata_sha}^{{tree}}") != r.kata_tree:
            problems.append(f"{r.run_id}: `kata_tree` {r.kata_tree} is not the tree of `kata_sha` {r.kata_sha}")
    return problems


# The committed evidence kit, and the manifest of the kit a run snapshotted, whose lines it
# must match (THE KIT, above).
KIT = "scripts/evidence-kit"
KIT_MANIFEST = "kit-sha256.txt"
KIT_MANIFEST_LINE = re.compile(r"(?P<sha>[0-9a-f]{64})  \./(?P<path>.+)")


def kit_problems(root, records):
    """Each record listing KIT_MANIFEST pins every regular file directly under KIT, by its
    name, at that file's sha256."""
    kit_dir = os.path.join(root, KIT)
    committed = {}
    if os.path.isdir(kit_dir):
        for name in sorted(os.listdir(kit_dir)):
            path = os.path.join(kit_dir, name)
            if os.path.isfile(path) and not os.path.islink(path):
                with open(path, "rb") as fh:
                    committed[name] = hashlib.sha256(fh.read()).hexdigest()
    problems = []
    for r in records:
        if KIT_MANIFEST not in {a["path"] for a in r.artifacts}:
            continue
        with open(os.path.join(root, RUNS, r.run_id, KIT_MANIFEST), encoding="utf-8", errors="replace") as fh:
            pinned = {m["path"]: m["sha"] for m in map(KIT_MANIFEST_LINE.fullmatch, fh.read().splitlines()) if m}
        for name, sha in committed.items():
            if name not in pinned:
                problems.append(f"{r.run_id}: {KIT_MANIFEST} pins no `./{name}`, which {KIT}/ commits as the kit's")
            elif pinned[name] != sha:
                problems.append(f"{r.run_id}: {KIT_MANIFEST} pins `./{name}` at {pinned[name]}, but {KIT}/{name} is {sha}")
    return problems


def load(runs_dir):
    records, problems = [], []
    if not os.path.isdir(runs_dir):
        return records, problems
    for name in sorted(os.listdir(runs_dir)):
        path = os.path.join(runs_dir, name)
        if not os.path.isdir(path):
            problems.append(f"{name}: not a run directory")
            continue
        rec, probs = validate(path)
        problems += probs
        if rec:
            records.append(rec)
    return records, problems


# ── rendering ────────────────────────────────────────────────────────────────


def _tokens(t):
    if isinstance(t, str):
        return t
    return f"in {t['input']} / cached {t['cache_read']} / cache-write {t['cache_write']} / out {t['output']}"


def _cost(r):
    if r.cost_recorded == "estimated":
        return f"estimated ${r.cost_recorded_usd:.4f}"
    return "unavailable"


def _cell(text):
    return str(text).replace("\n", " ").replace("|", "\\|")


def _unknown_usage(r):
    """The unknown usage beside a row's known tokens, in its reader's units: an E3 record's
    issued calls (on a void, a lower bound: no reader counted them) and unknown charges;
    another cell's `unmetered_calls`, which is ledger.py's unknown charges."""
    if r.cell != "E3":
        return f" (+{r.unmetered_calls} unknown charge(s))" if r.unmetered_calls else ""
    if not (r.unmetered_calls or r.unknown_charges):
        return ""
    calls = f"at least {r.unmetered_calls}" if r.outcome == "void" else f"{r.unmetered_calls}"
    return f" (+{calls} call(s), usage unknown, in {r.unknown_charges} unknown charge(s))"


def _row(r):
    spend = _tokens(r.tokens_recorded) + _unknown_usage(r)
    links = ", ".join(f"[{_cell(a['path'])}](runs/{r.run_id}/{a['path']})" for a in r.artifacts)
    cells = (
        f"[{r.run_id}](runs/{r.run_id}/run.toml)",
        r.case,
        r.harness,
        f"{r.surface} ({r.api_auth})" if r.api_auth else r.surface,
        f"`{r.kata_sha[:12]}` (tree `{r.kata_tree[:12]}`)",
        _vendor(r),
        f"{_cell(r.model)} ({_cell(r.effort)})",
        spend,
        _cell(_tokens(r.tokens_provider)),
        _cost(r),
        _cell(r.cost_provider),
        f"{r.wall_seconds} s",
        f"**{r.outcome}**",
    )
    if r.cell == "E3":
        cells += (_settlement(r),)
    if r.cell == "E2":
        cells += (_cell(r.variant or "—"), _cell(r.refined or "—"))
    source = r.void_reason if r.outcome == "void" else r.outcome_source
    cells += (_cell(source), links)
    return "| " + " | ".join(cells) + " |"


def _vendor(r):
    if r.vendor_version:
        return f"{VENDOR_VERSION[r.harness][0]} `{_cell(r.vendor_version)}`"
    return f"nanocode `{r.nanocode_rev[:12]}`"


def _settlement(r):
    observed = r.settlement
    if r.settlement_detail:
        observed += f": {_cell(r.settlement_detail)}"
    return f"{observed} (expected {EXPECTED_SETTLEMENT[r.case]})"


def _coverage(cell, recs):
    harnesses = CELL_HARNESSES[cell]
    lines = ["| Case | " + " | ".join(harnesses) + " |", "|---|" + "---|" * len(harnesses)]
    for case in CASES[cell]:
        cells = []
        for h in harnesses:
            if (cell, case) == ("E2", "refine"):
                cells.append(_refine_cell(recs, h))
                continue
            mine = [r for r in recs if r.case == case and r.harness == h]
            if not mine:
                cells.append("not yet run")
                continue
            counted = [r for r in mine if r.outcome != "void"]
            passed = sum(r.outcome == "pass" for r in counted)
            void = len(mine) - len(counted)
            text = f"{passed} pass of {len(counted)} run(s)"
            cells.append(text + (f", {void} void" if void else ""))
        lines.append(f"| {case} | " + " | ".join(cells) + " |")
    return lines


def _refine_cell(recs, harness):
    """The refine cell on one harness: its first REFINE_RUNS non-void run's outcome and
    `refined`, with the runs it did not count and the void ones beside it."""
    runs, extra, void = counted_runs(recs, "E2", "refine", harness, REFINE_RUNS)
    if not runs:
        return "not yet run" + _counted_notes(0, void)
    return ", ".join(f"{r.outcome}, refined {r.refined}" for r in runs) + _counted_notes(extra, void)


def render_cell(cell, records):
    recs = sorted((r for r in records if r.cell == cell), key=lambda r: r.run_id)
    out = _coverage(cell, recs)
    out.append("")
    if not recs:
        out.append(f"No {cell} run is recorded: {cell} has not yet run.")
        return "\n".join(out)
    columns = [
        "Run", "Case", "Harness", "Surface", "kata", "Vendor", "Model (effort)", "Tokens, kata",
        "Tokens, provider", "Cost, kata", "Cost, provider", "Wall", "Outcome",
    ]
    if cell == "E3":
        columns.append("Settlement, observed (expected)")
    if cell == "E2":
        columns += ["Variant", "Refined"]
    columns += ["Read from", "Artifacts"]
    out.append("| " + " | ".join(columns) + " |")
    out.append("|---" * len(columns) + "|")
    out.extend(_row(r) for r in recs)
    return "\n".join(out)


def counted_runs(records, cell, case, harness, n=PARITY_RUNS):
    """The runs counted for one case on one harness: the first `n` non-void runs by
    `started_utc` (then run id), how many non-void runs it left uncounted, and how many
    void runs it skipped."""
    mine = [r for r in records if r.cell == cell and r.case == case and r.harness == harness]
    live = sorted((r for r in mine if r.outcome != "void"), key=lambda r: (r.started_utc, r.run_id))
    return live[:n], max(0, len(live) - n), len(mine) - len(live)


def _counted_notes(extra, void):
    notes = [f"+{extra} not counted"] * bool(extra) + [f"{void} void"] * bool(void)
    return f" ({', '.join(notes)})" if notes else ""


def round_problems(records):
    """The counted round's refusals, across records: every E1/E2 parity run and every E2
    refine run on one `kata_sha`; every counted E2 pr run (the first `PARITY_RUNS` non-void on each harness,
    both pairs) on one `variant`; and each E1 case's counted runs on a harness submitted
    through `E1_SURFACES` only, with each of them among the counted runs once no later run
    can supply the missing one (a later run never replaces a counted one)."""
    problems = []
    shas = {}
    for r in records:
        if (r.cell, r.case) in ROUND_KEYS:
            shas.setdefault(r.kata_sha, []).append(r.run_id)
    if len(shas) > 1:
        named = "; ".join(f"`{sha}` ({len(ids)} run(s), e.g. {min(ids)})" for sha, ids in sorted(shas.items()))
        problems.append(
            f"the counted round mixes kata_sha: {named}; every E1/E2 parity run and E2 refine run, of both "
            "pairs, runs one pinned commit"
        )
    variants = {}
    for h in CELL_HARNESSES["E2"]:
        for case in PARITY_CASES["E2"]:
            for r in counted_runs(records, "E2", case, h)[0]:
                variants.setdefault(r.variant, []).append(r.run_id)
    if len(variants) > 1:
        named = "; ".join(f"`{v}` ({len(ids)} run(s), e.g. {min(ids)})" for v, ids in sorted(variants.items()))
        problems.append(
            f"the counted E2 pr runs differ in variant: {named}; every counted E2 pr run of both pairs runs one "
            "task variant"
        )
    for h in CELL_HARNESSES["E1"]:
        for case in PARITY_CASES["E1"]:
            runs, _, _ = counted_runs(records, "E1", case, h)
            off = [r for r in runs if r.surface not in E1_SURFACES]
            missing = [s for s in E1_SURFACES if s not in {r.surface for r in runs}]
            for r in off:
                problems.append(
                    f"{h} E1 {case}: counted run {r.run_id} is submitted through {r.surface}; a counted E1 run "
                    f"is submitted through {' or '.join(E1_SURFACES)}"
                )
            if not off and len(missing) > PARITY_RUNS - len(runs):
                problems.append(
                    f"{h} E1 {case}: the first {PARITY_RUNS} non-void runs lack a {' or '.join(missing)} run, and no "
                    "later run can replace one"
                )
    return problems


def render_parity(records):
    return "\n\n".join(_render_pair(pair, records) for pair in PAIRS)


def _render_pair(pair, records):
    """One pair's parity table and verdict, over that pair's two harnesses only."""
    harnesses = (pair.baseline, pair.nanocode)
    out = [
        f"**{pair.name} pair**: `{pair.baseline}` (baseline) vs `{pair.nanocode}`, on "
        f"{pair.model} / {pair.effort}.",
        "",
        "| Harness | " + " | ".join(f"{cell} {case}" for cell, case in PARITY_KEYS) + " |",
        "|---|" + "---|" * len(PARITY_KEYS),
    ]
    counted = {}
    for h in harnesses:
        row = []
        for cell, case in PARITY_KEYS:
            runs, extra, void = counted_runs(records, cell, case, h)
            counted[(h, cell, case)] = runs
            passes = sum(r.outcome == "pass" for r in runs)
            if not runs:
                row.append("not yet run" + _counted_notes(0, void))
                continue
            row.append(f"{passes} pass of {len(runs)}" + _counted_notes(extra, void))
        out.append(f"| {h} | " + " | ".join(row) + " |")
    out.append("")
    runs = [r for rs in counted.values() for r in rs]
    short = [f"{h} {cell} {case}" for (h, cell, case), rs in counted.items() if len(rs) < PARITY_RUNS]
    fewer = [
        f"{cell} {case}"
        for cell, case in PARITY_KEYS
        if sum(r.outcome == "pass" for r in counted[(pair.nanocode, cell, case)])
        < sum(r.outcome == "pass" for r in counted[(pair.baseline, cell, case)])
    ]
    verdict = f"{pair.name} parity:"
    if not runs:
        out.append(f"{verdict} not yet run.")
    elif short:
        out.append(f"{verdict} not met — fewer than {PARITY_RUNS} counted runs: {'; '.join(short)}.")
    elif fewer:
        out.append(f"{verdict} not met — {pair.nanocode} passes fewer counted runs than {pair.baseline}: {'; '.join(fewer)}.")
    else:
        out.append(
            f"{verdict} met — the first {PARITY_RUNS} non-void runs of each case on each harness of the pair "
            f"ran kata `{runs[0].kata_sha[:12]}`, and {pair.nanocode} passes at least as many of them as "
            f"{pair.baseline} in every case."
        )
    return "\n".join(out)


SECTIONS = (*CELLS, "parity")


def render_section(name, records):
    return render_parity(records) if name == "parity" else render_cell(name, records)


def _fence(name):
    return f"<!-- evidence:{name}:begin -->", f"<!-- evidence:{name}:end -->"


def splice(page, records):
    """Return (new_page, [problem]) with every fenced section re-rendered."""
    problems = []
    for name in SECTIONS:
        begin, end = _fence(name)
        if page.count(begin) != 1 or page.count(end) != 1 or page.index(begin) > page.index(end):
            problems.append(f"{PAGE}: needs exactly one `{begin}` … `{end}` pair")
            continue
        head, rest = page.split(begin, 1)
        _old, tail = rest.split(end, 1)
        page = f"{head}{begin}\n{render_section(name, records)}\n{end}{tail}"
    return page, problems


def run(root, write, archive_root=ARCHIVE_ROOT):
    records, problems = load(os.path.join(root, RUNS))
    problems += round_problems(records)
    problems += provenance_problems(root, records, archive_root)
    problems += kit_problems(root, records)
    page_path = os.path.join(root, PAGE)
    with open(page_path, encoding="utf-8") as fh:
        page = fh.read()
    new, splice_problems = splice(page, records)
    problems += splice_problems
    if write and not problems:
        if new != page:
            with open(page_path, "w", encoding="utf-8") as fh:
                fh.write(new)
    elif not write and new != page and not splice_problems:
        problems.append(f"{PAGE}: its rendered sections differ from the run records (run `just evidence-render`)")
    return records, problems


def cmd(write, root=ROOT, out=sys.stdout, err=sys.stderr, archive_root=ARCHIVE_ROOT):
    records, problems = run(root, write, archive_root)
    if problems:
        print(f"evidence-page: REFUSED — {len(problems)} problem(s):", file=err)
        for p in problems:
            print(f"  {p}", file=err)
        return 1
    verb = "rendered" if write else "ok"
    print(f"evidence-page: {verb} — {len(records)} run record(s); the page shows exactly them", file=out)
    return 0


# ── self-test ────────────────────────────────────────────────────────────────

GOOD = {
    "cell": "E1",
    "case": "seeded-pr",
    "harness": "nanocode-openai",
    "surface": "cli",
    "kata_sha": RETIRED_BASELINE_SHA,
    "kata_tree": "c" * 40,
    "nanocode_rev": "b" * 40,
    "model": "gpt-6-luna",
    "effort": "medium",
    "credential_mode": "subscription",
    "capsule_network": "offline",
    "started_utc": "2026-11-01T12:00:00Z",
    "wall_seconds": 300,
    "outcome": "pass",
    "outcome_source": "oracles.txt: 8 of 8 PASS",
    "tokens_recorded": {"input": 10, "cache_read": 2, "cache_write": 0, "output": 5},
    "unmetered_calls": 0,
    "tokens_provider": "unavailable: a subscription login has no per-token view",
    "cost_recorded": "unavailable",
    "cost_provider": "unavailable: subscription",
    "artifacts": [{"path": "oracles.txt", "what": "e1-run.sh's line per oracle"}],
}
# The outcome source of a cell or case no kit writes oracles.txt for (E2 mismatch, E3, E9),
# planted with files=("oracle.txt",).
ELSEWHERE = {
    "outcome_source": "oracle.txt: the cell's oracle reads",
    "artifacts": [{"path": "oracle.txt", "what": "the oracle reads"}],
}

# The kit's oracle names for an E1 run (e1-run.sh), either case, in its order.
E1_ORACLE_NAMES = (
    "terminal-completed",
    "frozen-head-is-forge-head",
    "review-validates-and-scores",
    "remote-unchanged",
    "no-target-pin-left",
    "stages-read",
    "turns-read",
    "spend-read",
)
# The kit's oracle names for an E2 pr run (e2-oracles.sh), in its order.
PR_ORACLE_NAMES = (
    "terminal-completed",
    "variant",
    "commit-subject",
    "parent-is-trunk",
    "tip-not-empty",
    "remote-branch",
    "one-open-pr",
    "clone-check",
    "oracle-e2",
    "kit-intact",
)
# The artifacts the kit writes for every E2 pr and refine run.
PR_ARTIFACTS = (
    "oracles.txt",
    "observed.toml",
    "capsule-path.txt",
    "kit-sha256.txt",
    "clone-check.txt",
    "oracle.txt",
    "test-iterations.txt",
    "refined.txt",
    "stages.txt",
    "turns.txt",
    "spend.toml",
    "pr.json",
    "remote-branch.txt",
    "tip.txt",
    "clone-path.txt",
)
# The kit's oracle names for an E2 refine-cell run (e2-oracles.sh), in its order: a pr
# run's but `kit-intact`, the refine cell's eight, then `kit-intact`.
REFINE_ORACLE_NAMES = (
    *PR_ORACLE_NAMES[:-1],
    "gate-bound",
    "gate-unseen",
    "refined",
    "final-gate",
    "refinecheck-ran",
    "gate-unnamed",
    "clone-gate",
    "oracle-align",
    "kit-intact",
)
# The artifacts the kit writes for every E2 refine-cell run: a pr run's and the refine six.
REFINE_ARTIFACTS = (
    *PR_ARTIFACTS,
    "refinecheck.txt",
    "gate-unnamed.txt",
    "clone-gate.txt",
    "oracle-align.txt",
    "change-refine.star",
    "params-sha256.txt",
)
# Synthetic refine-cell artifacts in the shape of the kit's (a real run's content stays
# outside the tree): an observed.toml with its comment lines, the oracles.txt of a pass,
# and that of a fail whose first iteration passed, so it did not refine.
REFINE_OBSERVED = """\
# e2-oracles.sh: the record's OBSERVED fields (a synthetic file in the kit's shape)
variant = "refine-cell"
refined = "yes"
# iterations = 2
# final_test = "passed"
# refine_cause = suite+gate (iteration 0's feedback)
# iter0_gate_fails = G1-sample-one G2-sample-two C1-sample-three G3-sample-four
"""
REFINE_ORACLES = "".join(f"PASS {o}\n" for o in REFINE_ORACLE_NAMES)
REFINE_FAIL_ORACLES = REFINE_ORACLES.replace("PASS refined\n", "FAIL refined: iterations 0:passed\n")
# A pr run's oracles.txt as an older kit wrote it, before `variant` and `kit-intact` were
# oracles and while `refined` was one: nine lines, which a pr record now refuses.
OLD_KIT_PR_ORACLES = "".join(f"PASS {o}\n" for o in PR_ORACLE_NAMES if o not in ("variant", "kit-intact"))
OLD_KIT_PR_ORACLES += "FAIL refined: test#iter-0 passed\n"


def _toml_value(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, str):
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(v, dict):
        return "{ " + ", ".join(f"{k} = {_toml_value(x)}" for k, x in v.items()) + " }"
    if isinstance(v, list):
        return "[" + ", ".join(_toml_value(x) for x in v) + "]"
    raise TypeError(type(v))


def _e1_oracles(d):
    """e1-run.sh's oracles.txt for `d`'s outcome: every oracle PASS, or the review's FAIL."""
    lines = [f"PASS {o}" for o in E1_ORACLE_NAMES]
    if d.get("outcome") == "fail":
        lines[2] = "FAIL review-validates-and-scores: score-e1: FAIL seeded 2/3"
    return "".join(f"{line}\n" for line in lines)


def _write_run(runs, d, name=None, files=("oracles.txt",), raw=None, link=None, contents=None):
    """Plant one run directory: `run.toml` from `d` (or `raw`), each of `files` holding
    `x` (an E1 run's `oracles.txt` instead holds e1-run.sh's eight lines, one FAIL on a
    fail), each of `contents` (path -> text or bytes) holding its content."""
    name = name or expected_run_id(d)
    path = os.path.join(runs, name)
    os.makedirs(path)
    toml_path = os.path.join(path, "run.toml")
    if link and link[0] == "run.toml":
        # The real record sits outside the run directory; the directory holds only a link.
        toml_path = os.path.join(runs, "..", "outside.toml")
        os.symlink(os.path.abspath(toml_path), os.path.join(path, "run.toml"))
    with open(toml_path, "w", encoding="utf-8") as fh:
        fh.write(raw if raw is not None else "".join(f"{k} = {_toml_value(v)}\n" for k, v in d.items()))
    planted = {f: _e1_oracles(d) if f == "oracles.txt" and d.get("cell") == "E1" else "x\n" for f in files}
    for f, text in {**planted, **(contents or {})}.items():
        os.makedirs(os.path.dirname(os.path.join(path, f)), exist_ok=True)
        with open(os.path.join(path, f), "wb") as fh:
            fh.write(text if isinstance(text, bytes) else text.encode("utf-8"))
    if link and link[0] != "run.toml":
        os.symlink(link[1], os.path.join(path, link[0]))
    return name


def _skeleton():
    parts = ["# page\n"]
    for name in SECTIONS:
        begin, end = _fence(name)
        parts.append(f"\n{begin}\nstale\n{end}\n")
    return "".join(parts)


def _mk_root(tmp):
    root = tempfile.mkdtemp(dir=tmp)
    os.makedirs(os.path.join(root, RUNS))
    with open(os.path.join(root, PAGE), "w", encoding="utf-8") as fh:
        fh.write(_skeleton())
    return root


def _quiet(write, root, archive_root=ARCHIVE_ROOT):
    import io

    out, err = io.StringIO(), io.StringIO()
    rc = cmd(write, root, out, err, archive_root=archive_root)
    return rc, err.getvalue()


# A hermetic git: no user or system config (so no signing), a fixed identity.
GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "evidence self-test",
    "GIT_AUTHOR_EMAIL": "self-test@example.test",
    "GIT_COMMITTER_NAME": "evidence self-test",
    "GIT_COMMITTER_EMAIL": "self-test@example.test",
}


def _git(root, *args):
    import subprocess

    env = {**os.environ, **GIT_ENV}
    return subprocess.run(["git", "-C", root, *args], env=env, capture_output=True, text=True, check=True).stdout.strip()


def _archive(root):
    """Make `root` a repository with an archive history: a root commit, the commit under
    test on main (HEAD), and a side commit that is not an ancestor of HEAD. Returns
    (root commit, commit under test, its tree, side commit)."""
    _git(root, "init", "-q", "-b", "main")
    _git(root, "commit", "-q", "--allow-empty", "-m", "root")
    first = _git(root, "rev-parse", "HEAD")
    _git(root, "checkout", "-q", "-b", "side")
    _git(root, "commit", "-q", "--allow-empty", "-m", "side")
    side = _git(root, "rev-parse", "HEAD")
    _git(root, "checkout", "-q", "main")
    with open(os.path.join(root, "src.txt"), "w", encoding="utf-8") as fh:
        fh.write("the source under test\n")
    _git(root, "add", "src.txt")
    _git(root, "commit", "-q", "-m", "under test")
    tested = _git(root, "rev-parse", "HEAD")
    return first, tested, _git(root, "rev-parse", "HEAD^{tree}"), side


def self_test():
    failures = []
    refusals = []

    def expect_refused(label, d, needle, **kw):
        refusals.append(label)
        with tempfile.TemporaryDirectory(prefix="evidence-page-") as tmp:
            root = _mk_root(tmp)
            _write_run(os.path.join(root, RUNS), d, **kw)
            try:
                rc, err = _quiet(True, root)
            except Exception as exc:  # an accepted record the render cannot show
                rc, err = None, f"raised {exc!r}"
            if rc != 1 or needle not in err:
                failures.append(f"{label}: rc={rc}, want a refusal naming {needle!r}; got {err.strip()!r}")

    def edit(**changes):
        d = {**GOOD, **changes}
        return {k: v for k, v in d.items() if v is not None}

    # The Anthropic pair's pin, and a valid claude-agent-acp record's fields.
    anthropic = {"model": "claude-sonnet-5-5", "credential_mode": "api_key"}
    acp = {**anthropic, "harness": "claude-agent-acp", "capsule_network": "vendor-egress-only", "vendor_version": "0.79.0"}

    # 1. A valid record renders and then checks clean; the page names its run id.
    with tempfile.TemporaryDirectory(prefix="evidence-page-") as tmp:
        root = _mk_root(tmp)
        name = _write_run(os.path.join(root, RUNS), GOOD)
        rc, err = _quiet(True, root)
        rc2, err2 = _quiet(False, root)
        with open(os.path.join(root, PAGE), encoding="utf-8") as fh:
            page = fh.read()
        if rc or rc2:
            failures.append(f"a valid record is refused: {err}{err2}")
        if (
            f"[{name}](runs/{name}/run.toml)" not in page
            or f"[oracles.txt](runs/{name}/oracles.txt)" not in page
            or GOOD["outcome_source"] not in page
            or "1 pass of 1 run(s)" not in page
        ):
            failures.append("the render does not show the valid record")
        # 2. A page edited to claim a row no record backs is refused.
        with open(os.path.join(root, PAGE), "w", encoding="utf-8") as fh:
            fh.write(page.replace("1 pass of 1 run(s)", "3 pass of 3 run(s)"))
        rc, err = _quiet(False, root)
        if rc != 1 or "differ from the run records" not in err:
            failures.append("a page claiming more than its records is accepted")

    # 2a. An E1 pass with usage kata does not know is a valid record: kata's known tokens,
    #     and the unknown charges (ledger.py's count, which the kit copies into
    #     `unmetered_calls`) beside them, never folded in as 0.
    with tempfile.TemporaryDirectory(prefix="evidence-page-") as tmp:
        root = _mk_root(tmp)
        _write_run(os.path.join(root, RUNS), {**GOOD, "unmetered_calls": 2})
        rc, err = _quiet(True, root)
        with open(os.path.join(root, PAGE), encoding="utf-8") as fh:
            page = fh.read()
        if rc or "| in 10 / cached 2 / cache-write 0 / out 5 (+2 unknown charge(s)) |" not in page:
            failures.append(f"an E1 pass with unknown charges does not render them beside its tokens: {err.strip()!r}")

    # 2a-E3. An E3 record states both units: the rig's issued calls of unknown usage and
    #        ledger.py's unknown charges. A killed attempt that issued 4 calls is 1 charge
    #        (P3); P1's never-sent attempt is 1 charge and 0 calls; a void's issued calls are
    #        a lower bound, rendered so.
    e3_base = {**GOOD, **ELSEWHERE, "cell": "E3", "settlement": "proven-ambiguous"}
    for label, d, want in (
        ("a P3 pass, 4 calls in 1 charge", {**e3_base, "case": "P3", "unmetered_calls": 4, "unknown_charges": 1},
         "out 5 (+4 call(s), usage unknown, in 1 unknown charge(s)) |"),
        ("a P1 pass, 0 calls in 1 charge", {**e3_base, "case": "P1", "unmetered_calls": 0, "unknown_charges": 1},
         "out 5 (+0 call(s), usage unknown, in 1 unknown charge(s)) |"),
        ("a P1-host pass, 0 calls in 3 charges",
         {**e3_base, "case": "P1-host", "unmetered_calls": 0, "unknown_charges": 3},
         "out 5 (+0 call(s), usage unknown, in 3 unknown charge(s)) |"),
        ("a P2 void, a lower bound", {**e3_base, "case": "P2", "outcome": "void", "void_reason": "oracle.txt: x",
                                      "settlement": "other", "settlement_detail": "void, not judged: x",
                                      "unmetered_calls": 1, "unknown_charges": 1},
         "out 5 (+at least 1 call(s), usage unknown, in 1 unknown charge(s)) |"),
    ):
        with tempfile.TemporaryDirectory(prefix="evidence-page-") as tmp:
            root = _mk_root(tmp)
            _write_run(os.path.join(root, RUNS), d, files=("oracle.txt",))
            rc, err = _quiet(True, root)
            with open(os.path.join(root, PAGE), encoding="utf-8") as fh:
                page = fh.read()
            if rc or want not in page:
                failures.append(f"an E3 record ({label}) is refused or does not render its two counts: {err.strip()!r}")

    # 2a'. The provider side under an API key: the ruled "not attributable" reason, or the
    #      provider's own figures.
    for label, provider in (
        ("not attributable", {"tokens_provider": "unavailable: per-run provider usage not attributable", "cost_provider": "unavailable: per-run provider usage not attributable"}),
        ("the provider's figures", {"tokens_provider": {"input": 9, "cache_read": 0, "cache_write": 0, "output": 4}, "cost_provider": "$0.0123"}),
    ):
        with tempfile.TemporaryDirectory(prefix="evidence-page-") as tmp:
            root = _mk_root(tmp)
            _write_run(os.path.join(root, RUNS), {**GOOD, "credential_mode": "api_key", **provider})
            rc, err = _quiet(True, root)
            if rc:
                failures.append(f"a record stating the provider side as {label} is refused: {err.strip()!r}")

    # 2a''. A harness PRICED holds under an API key: a nanocode-anthropic estimate is a valid
    #       record (`billing_backend` prices nanocode_anthropic from Anthropic's list prices).
    with tempfile.TemporaryDirectory(prefix="evidence-page-") as tmp:
        root = _mk_root(tmp)
        priced = {"harness": "nanocode-anthropic", "model": "claude-sonnet-5-5", "credential_mode": "api_key"}
        _write_run(os.path.join(root, RUNS), {**GOOD, **priced, "cost_recorded": "estimated", "cost_recorded_usd": 0.01})
        rc, err = _quiet(True, root)
        if rc:
            failures.append(f"a priced nanocode-anthropic api_key record is refused: {err.strip()!r}")

    # 2b. An E3 record renders its observed settlement beside the expected one.
    with tempfile.TemporaryDirectory(prefix="evidence-page-") as tmp:
        root = _mk_root(tmp)
        p3 = {**GOOD, **ELSEWHERE, "cell": "E3", "case": "P3", "settlement": "proven-ambiguous", "unknown_charges": 0}
        _write_run(os.path.join(root, RUNS), p3, files=("oracle.txt",))
        rc, err = _quiet(True, root)
        with open(os.path.join(root, PAGE), encoding="utf-8") as fh:
            page = fh.read()
        if rc or "| proven-ambiguous (expected proven-ambiguous) |" not in page:
            failures.append(f"an E3 record does not render its settlement: {err}")
        if "Settlement, observed (expected)" not in page:
            failures.append("the E3 table has no settlement column")

    # 2b'. The E3 matrix's anthropic arm (D2 §5.4): an E3 record on nanocode-anthropic
    #      validates, and the E3 coverage table has its column.
    with tempfile.TemporaryDirectory(prefix="evidence-page-") as tmp:
        root = _mk_root(tmp)
        p2 = {**GOOD, **ELSEWHERE, "cell": "E3", "case": "P2", "settlement": "proven-ambiguous", "harness": "nanocode-anthropic",
              "unknown_charges": 0}
        _write_run(os.path.join(root, RUNS), {**p2, "model": "claude-sonnet-5-5", "credential_mode": "api_key"}, files=("oracle.txt",))
        rc, err = _quiet(True, root)
        with open(os.path.join(root, PAGE), encoding="utf-8") as fh:
            page = fh.read()
        if rc or _quiet(False, root)[0]:
            failures.append(f"an E3 record on nanocode-anthropic is refused: {err.strip()!r}")
        if "| Case | nanocode-openai | nanocode-anthropic |" not in page or "| P2 | not yet run | 1 pass of 1 run(s) |" not in page:
            failures.append("the E3 coverage table does not show the nanocode-anthropic arm")

    # 2b''. E9's anthropic arm: an E9 record on nanocode-anthropic validates, and the E9
    #       coverage table has its column (the guest logs in with the API key, no browser).
    with tempfile.TemporaryDirectory(prefix="evidence-page-") as tmp:
        root = _mk_root(tmp)
        e9 = {**GOOD, **ELSEWHERE, **anthropic, "cell": "E9", "case": "clean-vm", "harness": "nanocode-anthropic"}
        _write_run(os.path.join(root, RUNS), e9, files=("oracle.txt",))
        rc, err = _quiet(True, root)
        with open(os.path.join(root, PAGE), encoding="utf-8") as fh:
            page = fh.read()
        if rc or _quiet(False, root)[0]:
            failures.append(f"an E9 record on nanocode-anthropic is refused: {err.strip()!r}")
        if "| clean-vm | not yet run | 1 pass of 1 run(s) |" not in page:
            failures.append("the E9 coverage table does not show the nanocode-anthropic arm")

    # 2c. The Anthropic pair's records validate and render: the baseline names its vendor's
    #     version line, nanocode its revision.
    with tempfile.TemporaryDirectory(prefix="evidence-page-") as tmp:
        root = _mk_root(tmp)
        pin = {"model": "claude-sonnet-5-5", "credential_mode": "api_key", "nanocode_rev": None}
        _write_run(os.path.join(root, RUNS), {**GOOD, **pin, "harness": "nanocode-anthropic", "nanocode_rev": "b" * 40})
        acp_run = {**GOOD, **pin, "harness": "claude-agent-acp", "capsule_network": "vendor-egress-only", "vendor_version": "0.79.0"}
        _write_run(os.path.join(root, RUNS), {k: v for k, v in acp_run.items() if v is not None})
        rc, err = _quiet(True, root)
        with open(os.path.join(root, PAGE), encoding="utf-8") as fh:
            page = fh.read()
        if rc or _quiet(False, root)[0]:
            failures.append(f"the Anthropic pair's records are refused: {err.strip()!r}")
        if "| claude-agent-acp `0.79.0` |" not in page or "| nanocode `bbbbbbbbbbbb` |" not in page:
            failures.append("the Anthropic pair's rows do not name their vendor")
        if "| seeded-pr | not yet run | not yet run | 1 pass of 1 run(s) | 1 pass of 1 run(s) |" not in page:
            failures.append("the E1 coverage table does not show the Anthropic pair's columns")

    # 3. With no record, every section is "not yet run", and the page checks clean.
    with tempfile.TemporaryDirectory(prefix="evidence-page-") as tmp:
        root = _mk_root(tmp)
        _quiet(True, root)
        with open(os.path.join(root, PAGE), encoding="utf-8") as fh:
            page = fh.read()
        for cell in CELLS:
            if f"No {cell} run is recorded: {cell} has not yet run." not in page:
                failures.append(f"empty render of {cell} does not say not yet run")
        if any(f"{p.name} parity: not yet run." not in page for p in PAIRS) or "pass of" in page:
            failures.append("the empty render claims a result")
        if _quiet(False, root)[0] != 0:
            failures.append("the empty render does not check clean")

    # 4. Each refusal fires on its planted record.
    expect_refused("missing field", edit(model=None), "missing field `model`")
    expect_refused("unknown field", edit(extra="x"), "unknown field `extra`")
    expect_refused("wrong type", edit(wall_seconds="300"), "field `wall_seconds` has the wrong type")
    expect_refused("bad toml", GOOD, "not valid TOML", raw="cell = \n")
    expect_refused("bad cell", edit(cell="E4"), "`cell` = 'E4' is not one of")
    expect_refused("bad case", edit(case="P1"), "is not a case of E1")
    expect_refused("bad harness", edit(harness="pi"), "`harness` = 'pi' is not one of")
    expect_refused("bad surface", edit(surface="web"), "`surface` = 'web'")
    expect_refused("bad outcome", edit(outcome="passed"), "`outcome` = 'passed'")
    expect_refused("rest without api_auth", edit(surface="rest"), "a rest run states api_auth")
    expect_refused("rest with bad api_auth", edit(surface="rest", api_auth="none"), "a rest run states api_auth")
    expect_refused("cli with api_auth", edit(api_auth="signed-token"), "a cli run states no api_auth")
    expect_refused(
        "E3 on codex-stock",
        edit(cell="E3", case="P1", harness="codex-stock", capsule_network="vendor-egress-only"),
        "E3 runs on nanocode-openai, nanocode-anthropic only",
    )
    expect_refused(
        "E3 on claude-agent-acp",
        edit(**{**acp, "cell": "E3", "case": "P1", "settlement": "proven-ambiguous"}),
        "E3 runs on nanocode-openai, nanocode-anthropic only",
    )
    expect_refused(
        "E9 on codex-stock",
        edit(**ELSEWHERE, cell="E9", case="clean-vm", harness="codex-stock", capsule_network="vendor-egress-only"),
        "E9 runs on nanocode-openai, nanocode-anthropic only",
        files=("oracle.txt",),
    )
    expect_refused(
        "E9 on claude-agent-acp",
        edit(**{**acp, **ELSEWHERE, "cell": "E9", "case": "clean-vm"}),
        "E9 runs on nanocode-openai, nanocode-anthropic only",
        files=("oracle.txt",),
    )
    expect_refused("codex-stock offline", edit(harness="codex-stock"), "a codex-stock capsule is vendor-egress-only")
    expect_refused("nanocode egress", edit(capsule_network="vendor-egress-only"), "a nanocode-openai capsule is offline")
    expect_refused("claude-agent-acp offline", edit(**{**acp, "capsule_network": "offline"}), "a claude-agent-acp capsule is vendor-egress-only")
    expect_refused(
        "nanocode-anthropic egress",
        edit(**anthropic, harness="nanocode-anthropic", capsule_network="vendor-egress-only"),
        "a nanocode-anthropic capsule is offline",
    )
    expect_refused("model off its pair", edit(model="gpt-other"), "in the OpenAI pair, whose model is gpt-6-luna, not 'gpt-other'")
    expect_refused("effort off its pair", edit(effort="high"), "in the OpenAI pair, whose effort is medium, not 'high'")
    expect_refused(
        "the other pair's model",
        edit(**{**acp, "model": "gpt-6-luna"}),
        "in the Anthropic pair, whose model is claude-sonnet-5-5, not 'gpt-6-luna'",
    )
    expect_refused("a harness in no pair", edit(harness="codex-openai"), "`harness` = 'codex-openai' is not one of")
    expect_refused(
        "E1 on nanocode-anthropic with the OpenAI pin",
        edit(harness="nanocode-anthropic"),
        "in the Anthropic pair, whose model is claude-sonnet-5-5, not 'gpt-6-luna'",
    )
    expect_refused(
        "priced subscription",
        edit(cost_recorded="estimated", cost_recorded_usd=0.01),
        "a subscription login meters no price",
    )
    expect_refused(
        "priced nanocode-openai",
        edit(credential_mode="api_key", cost_recorded="estimated", cost_recorded_usd=0.01),
        "kata prices no nanocode-openai turn",
    )
    expect_refused(
        "priced claude-agent-acp",
        edit(**acp, cost_recorded="estimated", cost_recorded_usd=0.01),
        "kata prices no claude-agent-acp turn",
    )
    expect_refused(
        "estimate without usd",
        edit(
            harness="codex-stock",
            capsule_network="vendor-egress-only",
            credential_mode="api_key",
            cost_recorded="estimated",
        ),
        "an estimated cost needs cost_recorded_usd",
    )
    expect_refused("usd while unavailable", edit(cost_recorded_usd=0.01), "cost_recorded_usd with an unavailable cost")
    expect_refused("short sha", edit(kata_sha="abc123"), "`kata_sha` must be 40 lowercase hex")
    codex_stock = {"harness": "codex-stock", "capsule_network": "vendor-egress-only", "vendor_version": "codex-cli 0.165.0"}
    for baseline in (codex_stock, acp):
        expect_refused(
            f"a {baseline['harness']} record off the counted round's build",
            edit(**baseline, kata_sha="d" * 40),
            f"{baseline['harness']} is a retired baseline",
        )
    expect_refused("bad nanocode rev", edit(nanocode_rev="B" * 40), "`nanocode_rev` must be 40 lowercase hex")
    expect_refused("bad started", edit(started_utc="2026-11-01 12:00"), "`started_utc` must be", name="e1-x")
    expect_refused("negative wall", edit(wall_seconds=-1), "`wall_seconds` is negative")
    expect_refused(
        "token keys",
        edit(tokens_recorded={"input": 1, "output": 2}),
        "tokens_recorded keys must be exactly",
    )
    expect_refused(
        "negative tokens",
        edit(tokens_recorded={"input": -1, "cache_read": 0, "cache_write": 0, "output": 0}),
        "tokens_recorded.input must be a non-negative integer",
    )
    expect_refused("provider tokens string", edit(tokens_provider="n/a"), 'tokens_provider string must be "unavailable: <reason>"')
    expect_refused("provider cost free text", edit(cost_provider="n/a"), '`cost_provider` must be "unavailable: <reason>" or the provider\'s figure')
    expect_refused("provider cost bare unavailable", edit(cost_provider="unavailable: "), '`cost_provider` must be')
    expect_refused("provider cost prose figure", edit(cost_provider="about $0.01"), '`cost_provider` must be')
    expect_refused("provider tokens blank reason", edit(tokens_provider="unavailable:   "), 'tokens_provider string must be "unavailable: <reason>"')
    expect_refused("recorded tokens string", edit(tokens_recorded="zero"), 'tokens_recorded string must be "unknown"')
    expect_refused("empty model", edit(model=" "), "`model` is empty")
    expect_refused("misnamed directory", GOOD, "the directory must be named", name="e1-run")
    expect_refused("absent artifact", GOOD, "artifact 'oracles.txt' is absent", files=())
    expect_refused(
        "escaping artifact",
        edit(artifacts=[{"path": "../oracles.txt", "what": "x"}]),
        "is outside the run directory",
    )
    expect_refused("unlisted file", GOOD, "file 'extra.log' is not listed", files=("oracles.txt", "extra.log"))
    expect_refused("no artifacts", edit(artifacts=[]), "no artifact listed", files=())
    expect_refused("unsourced outcome", edit(outcome_source="kata said it passed"), "outcome_source must start with")
    # A short artifact name inside the text is not a source: the path must lead it.
    expect_refused(
        "substring source",
        edit(artifacts=[{"path": "o", "what": "x"}], outcome_source="kata run show said pass"),
        "outcome_source must start with",
        files=("o",),
    )
    expect_refused(
        "source named late",
        edit(outcome_source="kata said pass; see oracles.txt: x"),
        "outcome_source must start with",
    )
    expect_refused("symlinked artifact", GOOD, "artifact 'oracles.txt' is a symbolic link", files=(), link=("oracles.txt", "/etc/hostname"))
    expect_refused(
        "symlinked unlisted file",
        GOOD,
        "'extra' is a symbolic link",
        link=("extra", "/etc/hostname"),
    )
    expect_refused("symlinked run.toml", GOOD, "its run.toml is a symbolic link", link=("run.toml", "/etc/hostname"))
    e3 = {"cell": "E3", "case": "P1", "settlement": "proven-ambiguous", "unknown_charges": 0}
    expect_refused("E3 without settlement", edit(cell="E3", case="P1"), "an E3 run states its observed `settlement`")
    e3_counts = {**e3, **ELSEWHERE}
    expect_refused("E3 without unknown_charges", edit(**{**e3_counts, "unknown_charges": None}),
                   "an E3 record states `unknown_charges`", files=("oracle.txt",))
    expect_refused("negative unknown_charges", edit(**{**e3_counts, "unknown_charges": -1}),
                   "`unknown_charges` is negative", files=("oracle.txt",))
    expect_refused("unknown_charges off E3", edit(unknown_charges=0), "only an E3 record states `unknown_charges`")
    expect_refused("E3 P2: 0 issued calls beside 1 charge", edit(**{**e3_counts, "case": "P2", "unknown_charges": 1}),
                   "0 issued call(s) of unknown usage, fewer than its 1 `unknown_charges`", files=("oracle.txt",))
    expect_refused("E3 P2: more charges than issued calls",
                   edit(**{**e3_counts, "case": "P2", "unmetered_calls": 1, "unknown_charges": 2}),
                   "1 issued call(s) of unknown usage, fewer than its 2 `unknown_charges`", files=("oracle.txt",))
    expect_refused("E3 P2: an issued call with no charge",
                   edit(**{**e3_counts, "case": "P2", "unmetered_calls": 1}),
                   "1 issued call(s) of unknown usage beside 0 `unknown_charges`", files=("oracle.txt",))
    # P1 and P1-host: exactly 0 issued calls, beside any number of charges; every other pair is
    # refused, a charge per call included.
    for label, case, calls, charges in (
        ("E3 P1: an issued call with no charge", "P1", 1, 0),
        ("E3 P1: an issued call beside a charge", "P1", 1, 1),
        ("E3 P1: 2 issued calls beside 3 charges", "P1", 2, 3),
        ("E3 P1-host: 1 issued call beside 2 charges", "P1-host", 1, 2),
    ):
        expect_refused(label, edit(**{**e3_counts, "case": case, "unmetered_calls": calls, "unknown_charges": charges}),
                       f"{calls} issued call(s) of unknown usage on {case}, whose killed attempt is never sent",
                       files=("oracle.txt",))
    expect_refused("E3 bad settlement", edit(**{**e3, "settlement": "ok"}), "an E3 run states its observed `settlement`")
    expect_refused("settlement off E3", edit(settlement="proven-ambiguous"), "only an E3 run states `settlement`")
    expect_refused("pass off expected", edit(**{**e3, "settlement": "pr-opened-once"}), "a P1 pass settles proven-ambiguous, not pr-opened-once")
    expect_refused("other without detail", edit(**{**e3, "settlement": "other", "outcome": "fail"}), "`settlement_detail` is stated exactly")
    expect_refused("detail without other", edit(**{**e3, "settlement_detail": "x"}), "`settlement_detail` is stated exactly")
    expect_refused("accepted_by is no field", edit(**{**e3, "accepted_by": "restart-sweep"}), "unknown field `accepted_by`")
    expect_refused("bad artifact entry", edit(artifacts=[{"path": "oracle.txt"}]), "must be { path, what } strings")
    codex = {"harness": "codex-stock", "capsule_network": "vendor-egress-only", "nanocode_rev": None}
    expect_refused("codex-stock without vendor_version", edit(**codex), "a codex-stock run states `vendor_version`")
    expect_refused(
        "codex-stock bad vendor_version",
        edit(**codex, vendor_version="0.157.1"),
        "a codex-stock run states `vendor_version`",
    )
    expect_refused(
        "vendor_version off a baseline",
        edit(vendor_version="codex-cli 0.157.1"),
        "only a codex-stock or claude-agent-acp run states `vendor_version`",
    )
    expect_refused("nanocode without nanocode_rev", edit(nanocode_rev=None), "a nanocode-openai run states `nanocode_rev`")
    expect_refused(
        "nanocode-anthropic without nanocode_rev",
        edit(**anthropic, harness="nanocode-anthropic", nanocode_rev=None),
        "a nanocode-anthropic run states `nanocode_rev`",
    )
    expect_refused(
        "claude-agent-acp without vendor_version",
        edit(**{**acp, "vendor_version": None}),
        "a claude-agent-acp run states `vendor_version`, the `claude-agent-acp --version` line",
    )
    expect_refused(
        "claude-agent-acp with codex's version line",
        edit(**{**acp, "vendor_version": "codex-cli 0.165.0"}),
        "a claude-agent-acp run states `vendor_version`",
    )
    expect_refused(
        "claude-agent-acp one-component version",
        edit(**{**acp, "vendor_version": "1"}),
        "a claude-agent-acp run states `vendor_version`",
    )
    expect_refused(
        "codex-stock two-component version",
        edit(**codex, vendor_version="codex-cli 0.165"),
        "a codex-stock run states `vendor_version`",
    )
    expect_refused("missing kata_tree", edit(kata_tree=None), "missing field `kata_tree`")
    expect_refused("short kata_tree", edit(kata_tree="abc"), "`kata_tree` must be 40 lowercase hex")
    expect_refused("void without reason", edit(outcome="void"), "a void run states `void_reason`")
    expect_refused(
        "void reason naming no artifact",
        edit(outcome="void", void_reason="the marker was missing"),
        "a void run states `void_reason`",
    )
    expect_refused("void reason off void", edit(void_reason="oracle.txt: x"), "only a void run states `void_reason`")
    expect_refused("pass with unknown tokens", edit(tokens_recorded="unknown"), "a pass states kata's token counts")
    expect_refused("missing unmetered_calls", edit(unmetered_calls=None), "missing field `unmetered_calls`")
    expect_refused("negative unmetered_calls", edit(unmetered_calls=-1), "`unmetered_calls` is negative")

    # 4c. E2's observed fields and its oracle lines (the kit's RUNBOOK §4, §4b).
    pr_oracles = "".join(f"PASS {o}\n" for o in PR_ORACLE_NAMES)
    one_fail = pr_oracles.replace("PASS oracle-e2", "FAIL oracle-e2: oracle-e2: 55 passed, 1 failed")
    codex_e2 = {"harness": "codex-stock", "capsule_network": "vendor-egress-only", "vendor_version": "codex-cli 0.165.0"}

    def e2(case="pr", oracles=None, names=None, **changes):
        """An E2 pr (or refine) record and its directory's contents: the kit's artifacts,
        with oracles.txt holding `oracles` (by default every oracle of the case PASS)."""
        refine = case == "refine"
        names = names or (REFINE_ARTIFACTS if refine else PR_ARTIFACTS)
        d = edit(
            **{
                "cell": "E2",
                "case": case,
                "variant": "refine-cell" if refine else "refine-addendum",
                "refined": "yes" if refine else "no",
                "outcome_source": "oracles.txt: e2-oracles.sh's line per oracle",
                "artifacts": [{"path": n, "what": "written by the E2 kit"} for n in names],
                **changes,
            }
        )
        contents = {n: "x\n" for n in names}
        if "oracles.txt" in names:
            contents["oracles.txt"] = oracles if oracles is not None else REFINE_ORACLES if refine else pr_oracles
        return d, contents

    def e2_refused(label, needle, **kw):
        d, contents = e2(**kw)
        expect_refused(label, d, needle, files=(), contents=contents)

    def e2_accepted(label, runs):
        """`runs`: (record, contents[, raw run.toml]) that must render and check clean."""
        with tempfile.TemporaryDirectory(prefix="evidence-page-") as tmp:
            root = _mk_root(tmp)
            for d, contents, *raw in runs:
                _write_run(os.path.join(root, RUNS), d, files=(), contents=contents, raw=raw[0] if raw else None)
            rc, err = _quiet(True, root)
            rc2, err2 = _quiet(False, root)
            with open(os.path.join(root, PAGE), encoding="utf-8") as fh:
                page = fh.read()
        if rc or rc2:
            failures.append(f"{label} is refused: {(err + err2).strip()!r}")
        return page

    # `variant` and `refined` are stated exactly on an E2 pr or refine run, of any outcome.
    expect_refused("variant on E1", edit(variant="refine-addendum"), "only an E2 pr or refine run states `variant`")
    expect_refused("refined on E3", edit(**e3, refined="no"), "only an E2 pr or refine run states `refined`")
    expect_refused("variant on E9", edit(cell="E9", case="clean-vm", variant="task-only"), "only an E2 pr or refine run states `variant`")
    expect_refused("variant on E2 mismatch", edit(cell="E2", case="mismatch", variant="refine-addendum"), "only an E2 pr or refine run states `variant`")
    expect_refused("refined on E2 mismatch", edit(cell="E2", case="mismatch", refined="no"), "only an E2 pr or refine run states `refined`")
    e2_refused("E2 pr without variant", "an E2 pr run states `variant`", variant=None)
    e2_refused("E2 pr without refined", "an E2 pr run states `refined`", refined=None)
    e2_refused("E2 refine without refined", "an E2 refine run states `refined`", case="refine", refined=None)
    e2_refused(
        "void E2 pr without variant",
        "an E2 pr run states `variant`",
        variant=None,
        outcome="void",
        void_reason="pr.json: the forge answered 502",
    )
    # A void pr or refine run states `variant` but need not state `refined`: a run whose kit
    # stopped before e2-oracles.sh ran has no observed.toml to copy it from. One it states is
    # still enumerated.
    void = {"names": ("pr.json",), "outcome": "void", "outcome_source": "pr.json: x", "void_reason": "pr.json: the forge answered 502"}
    e2_accepted("a void E2 pr run without refined", [e2(refined=None, **void)])
    e2_accepted("a void E2 refine run without refined", [e2(case="refine", refined=None, **void)])
    e2_refused("a void E2 pr run with refined outside REFINED", "`refined` = 'maybe' is not one of", refined="maybe", **void)
    # Each in its enumeration (strings: FIELDS refuses a bool).
    e2_refused("variant outside VARIANTS", "`variant` = 'refine' is not one of", variant="refine")
    e2_refused("refined outside REFINED", "`refined` = 'true' is not one of", refined="true")
    e2_refused("refined as a boolean", "field `refined` has the wrong type", refined=True)
    # A pr run's variant is task-only or refine-addendum; a refine run's is refine-cell.
    e2_refused("refine-cell on a pr run", "an E2 pr run's variant is task-only or refine-addendum, not 'refine-cell'", variant="refine-cell")
    e2_refused(
        "refine-addendum on a refine run",
        "an E2 refine run's variant is refine-cell, not 'refine-addendum'",
        case="refine",
        variant="refine-addendum",
    )
    e2_refused("task-only on a refine run", "an E2 refine run's variant is refine-cell, not 'task-only'", case="refine", variant="task-only")
    # A refine pass refined.
    e2_refused("a refine pass that did not refine", 'a refine pass states `refined = "yes"`', case="refine", refined="no")
    # A non-void pr or refine run's outcome is read from oracles.txt, the case's oracle count,
    # kit-intact last, passing exactly when every oracle passes.
    e2_refused("E2 pr outcome read elsewhere", "an E2 pr run's outcome_source is `oracles.txt: ...`", outcome_source="oracle.txt: the wrap oracle")
    e2_refused(
        "an older kit's nine pr oracles",
        "oracles.txt holds 9 oracle(s); an E2 pr run is judged by 10",
        oracles=OLD_KIT_PR_ORACLES,
        outcome="fail",
    )
    e2_refused("a refine run's oracles on a pr run", "oracles.txt holds 18 oracle(s); an E2 pr run is judged by 10", oracles=REFINE_ORACLES)
    e2_refused(
        "a refine run missing an oracle",
        "oracles.txt holds 17 oracle(s); an E2 refine run is judged by 18",
        case="refine",
        oracles=REFINE_ORACLES.replace("PASS gate-unnamed\n", ""),
    )
    e2_refused(
        "kit-intact not last",
        "the last oracle in oracles.txt is `kit-intact`",
        oracles=pr_oracles.replace("PASS oracle-e2\nPASS kit-intact\n", "PASS kit-intact\nPASS oracle-e2\n"),
    )
    e2_refused("a malformed oracle line", "oracles.txt line 1 is not `PASS <oracle>`", oracles="ok " + pr_oracles)
    e2_refused("a blank oracle line", "oracles.txt line 11 is not `PASS <oracle>`", oracles=pr_oracles + "\n")
    e2_refused("a pass with a FAIL oracle", "outcome 'pass' with 1 FAIL line(s) in oracles.txt", oracles=one_fail)
    e2_refused("a fail with every oracle PASS", "outcome 'fail' with 0 FAIL line(s) in oracles.txt", outcome="fail")
    e2_refused("oracles.txt not UTF-8", "oracles.txt is not UTF-8 text", oracles=b"PASS terminal-completed\xff\n")
    # Only a FAIL line carries a detail, after `: `; a carriage return is in no line.
    e2_refused(
        "a PASS line with a detail",
        "oracles.txt line 10 is not `PASS <oracle>`",
        oracles=pr_oracles.replace("PASS kit-intact\n", "PASS kit-intact: x\n"),
    )
    e2_refused(
        "a FAIL detail without its space",
        "oracles.txt line 9 is not `PASS <oracle>`",
        oracles=pr_oracles.replace("PASS oracle-e2\n", "FAIL oracle-e2:x\n"),
        outcome="fail",
    )
    e2_refused("CRLF oracle lines", "oracles.txt line 1 is not `PASS <oracle>`", oracles=pr_oracles.replace("\n", "\r\n"))
    e2_refused("CR-separated oracle lines", "oracles.txt line 1 is not `PASS <oracle>`", oracles=pr_oracles.replace("\n", "\r"))
    e2_refused(
        "a FAIL line ending in a carriage return",
        "oracles.txt line 9 is not `PASS <oracle>`",
        oracles=one_fail.replace("1 failed\n", "1 failed\r\n"),
        outcome="fail",
    )
    # The params file is never an artifact, by its name at any depth, on any E2 run.
    e2_refused(
        "the params file as an artifact",
        "artifact 'codex-stock.json' is named as the refine cell's params file",
        case="refine",
        names=(*REFINE_ARTIFACTS, "codex-stock.json"),
    )
    e2_refused(
        "the params file nested in the run directory",
        "artifact 'logs/codex-stock.json' is named as the refine cell's params file",
        case="refine",
        names=(*REFINE_ARTIFACTS, "logs/codex-stock.json"),
    )
    e2_refused(
        "the params file on a pr run",
        "artifact 'nanocode-openai.json' is named as the refine cell's params file",
        names=(*PR_ARTIFACTS, "nanocode-openai.json"),
    )

    # 4c'. Any other non-void run whose outcome_source reads `oracles.txt:` is judged by the
    #      same rules: an E1 run by e1-run.sh's eight lines (no last-oracle rule), and a cell
    #      or case no kit writes oracles.txt for is refused.
    e1_oracles = "".join(f"PASS {o}\n" for o in E1_ORACLE_NAMES)
    e1_fail = e1_oracles.replace(
        "PASS review-validates-and-scores\n",
        "FAIL review-validates-and-scores: score-e1: FAIL seeded 2/3 (unmatched 0 of 2 findings)\n",
    )

    def e1(oracles=e1_oracles, **changes):
        """An E1 record whose outcome is read from oracles.txt, holding `oracles`."""
        d = edit(
            outcome_source="oracles.txt: 8 of 8 PASS",
            artifacts=[{"path": "oracles.txt", "what": "e1-run.sh's line per oracle"}],
            **changes,
        )
        return d, {"oracles.txt": oracles}

    def e1_refused(label, needle, **kw):
        d, contents = e1(**kw)
        expect_refused(label, d, needle, files=(), contents=contents)

    e1_refused("an E1 pass with a FAIL oracle", "outcome 'pass' with 1 FAIL line(s) in oracles.txt", oracles=e1_fail)
    e1_refused("an E1 fail with every oracle PASS", "outcome 'fail' with 0 FAIL line(s) in oracles.txt", outcome="fail")
    e1_refused(
        "an E1 seeded-pr run missing an oracle",
        "oracles.txt holds 7 oracle(s); an E1 seeded-pr run is judged by 8",
        oracles=e1_oracles.replace("PASS spend-read\n", ""),
    )
    e1_refused(
        "an E1 public-pr run with an extra oracle",
        "oracles.txt holds 9 oracle(s); an E1 public-pr run is judged by 8",
        case="public-pr",
        oracles=e1_oracles + "PASS kit-intact\n",
    )
    e1_refused("an E1 malformed oracle line", "oracles.txt line 1 is not `PASS <oracle>`", oracles="ok\n" + e1_oracles)
    # An E1 run is judged by oracles.txt whatever its outcome_source cites: e1-run.sh always
    # writes it, so a pass citing another artifact over a FAIL oracle line is refused.
    d, contents = e1(oracles=e1_fail)
    d["outcome_source"] = "e1-run.log: the review looked right"
    d["artifacts"] = [*d["artifacts"], {"path": "e1-run.log", "what": "the run's log"}]
    contents["e1-run.log"] = "x\n"
    expect_refused(
        "an E1 pass citing another artifact over a FAIL oracle",
        d,
        "an E1 seeded-pr run's outcome_source is `oracles.txt: ...`",
        files=(),
        contents=contents,
    )
    d, contents = e1(**e3)
    expect_refused("an E3 run read from oracles.txt", d, "no kit judges an E3 P1 run by oracles.txt", files=(), contents=contents)
    # 4c''. THE KIT: a record's kit-sha256.txt pins each committed kit file at its bytes.
    e2_refused(
        "an E2 pr run that lists no kit manifest",
        "an E2 pr run lists kit-sha256.txt",
        names=tuple(n for n in PR_ARTIFACTS if n != "kit-sha256.txt"),
    )
    kit_body = b"#!/bin/sh\necho the committed kit\n"
    kit_sha = hashlib.sha256(kit_body).hexdigest()
    for label, manifest, needle in (
        ("a manifest pinning the committed kit", f"{'0' * 64}  ./other.sh\n{kit_sha}  ./run.sh\n", None),
        ("a manifest pinning other bytes", f"{'1' * 64}  ./run.sh\n", "kit-sha256.txt pins `./run.sh` at 1111"),
        ("a manifest that omits a committed kit file", f"{kit_sha}  ./other.sh\n", "kit-sha256.txt pins no `./run.sh`"),
        ("a manifest naming the file in another shape", f"{kit_sha} ./run.sh\n", "kit-sha256.txt pins no `./run.sh`"),
    ):
        if needle:
            refusals.append(label)
        d, contents = e2()
        contents["kit-sha256.txt"] = manifest
        with tempfile.TemporaryDirectory(prefix="evidence-page-") as tmp:
            root = _mk_root(tmp)
            os.makedirs(os.path.join(root, KIT))
            with open(os.path.join(root, KIT, "run.sh"), "wb") as fh:
                fh.write(kit_body)
            _write_run(os.path.join(root, RUNS), d, files=(), contents=contents)
            rc, err = _quiet(True, root)
        if (rc, needle is None or needle in err) != (1 if needle else 0, True):
            failures.append(f"{label}: rc={rc}, want {'a refusal naming ' + repr(needle) if needle else 'acceptance'}; got {err.strip()!r}")

    e2_accepted("an E1 fail read from oracles.txt", [e1(outcome="fail", oracles=e1_fail)])
    e2_accepted("a void E1 run's oracles.txt is not judged", [e1(outcome="void", void_reason="oracles.txt: x", oracles="junk\n")])

    # 4d. Accepted: `refined` constrains no pr outcome; a void run is judged by no oracle
    #     line; and refine-cell runs, run.toml carrying observed.toml's lines verbatim,
    #     comments included, render their observed fields and the refine row.
    page = e2_accepted("an E2 pr pass with refined = no", [e2()])
    if "| **pass** | refine-addendum | no |" not in page:
        failures.append("an E2 pr row does not show its variant and refined")
    e2_accepted("an E2 pr fail that refined", [e2(refined="yes", outcome="fail", oracles=one_fail)])
    e2_accepted(
        "a void E2 pr run without oracles.txt",
        [e2(names=("pr.json",), outcome="void", outcome_source="pr.json: x", void_reason="pr.json: the forge answered 502")],
    )
    fail_run = e2(
        case="refine",
        oracles=REFINE_FAIL_ORACLES,
        refined="no",
        outcome="fail",
        started_utc="2026-11-02T12:00:00Z",
        **codex_e2,
    )
    pass_d, pass_c = e2(case="refine", started_utc="2026-11-02T13:00:00Z", **codex_e2)
    pass_c["observed.toml"] = REFINE_OBSERVED
    raw = "".join(f"{k} = {_toml_value(v)}\n" for k, v in pass_d.items() if k not in ("variant", "refined"))
    page = e2_accepted("a refine-cell pass, observed.toml's lines in run.toml", [(pass_d, pass_c, raw + REFINE_OBSERVED)])
    if "| refine | pass, refined yes | not yet run | not yet run | not yet run |" not in page:
        failures.append("the refine row does not show the refine-cell pass")
    if "| **pass** | refine-cell | yes |" not in page:
        failures.append("the refine run's row does not show its variant and refined")
    page = e2_accepted("two refine-cell runs, the fail first", [fail_run, (pass_d, pass_c, raw + REFINE_OBSERVED)])
    if "| refine | fail, refined no (+1 not counted) | not yet run |" not in page:
        failures.append("the refine row does not show the first refine run, with the later one beside it")
    void_refine = e2(case="refine", outcome="void", void_reason="pr.json: the forge answered 502")
    page = e2_accepted("a void refine run", [void_refine])
    if "| refine | not yet run | not yet run (1 void) | not yet run | not yet run |" not in page:
        failures.append("the refine row does not read not yet run beside a void refine run")

    # 4b. A run directory that is itself a symbolic link is refused.
    with tempfile.TemporaryDirectory(prefix="evidence-page-") as tmp:
        root = _mk_root(tmp)
        name = _write_run(tmp, GOOD)
        os.symlink(os.path.join(tmp, name), os.path.join(root, RUNS, name))
        refusals.append("symlinked run directory")
        rc, err = _quiet(False, root)
        if rc != 1 or "the run directory or its run.toml is a symbolic link" not in err:
            failures.append(f"a symlinked run directory is accepted: {err.strip()!r}")

    # 5. A page missing a fence pair is refused rather than silently rendered.
    with tempfile.TemporaryDirectory(prefix="evidence-page-") as tmp:
        root = _mk_root(tmp)
        with open(os.path.join(root, PAGE), "w", encoding="utf-8") as fh:
            fh.write(_skeleton().replace("<!-- evidence:E9:end -->", ""))
        rc, err = _quiet(True, root)
        if rc != 1 or "evidence:E9:begin" not in err:
            failures.append("a page missing a fence is accepted")

    # 6. Parity, within each pair: the first three non-void runs of each case on each
    #    harness, the E1 ones including a CLI and a REST run, all on one kata, the pair's
    #    nanocode passing at least as many as its baseline in every case.
    def rec(cell, case, harness, outcome, i, **over):
        pair = PAIR_OF[harness]
        surface = ("cli", "rest", "cli")[i % 3] if cell == "E1" else "cli"
        auth = {"api_auth": "signed-token"} if surface == "rest" else {}
        return Record("x", {**GOOD, "cell": cell, "case": case, "harness": harness, "capsule_network": CAPSULE_NETWORK[harness], "model": pair.model, "outcome": outcome, "surface": surface, **auth, "started_utc": f"2026-11-01T12:00:{i:02}Z", **over})

    def parity(label, recs, needle, absent=None):
        text = render_parity(recs)
        if needle not in text or (absent and absent in text):
            verdicts = [line for line in text.splitlines() if " parity: " in line]
            failures.append(f"parity, {label}: want {needle!r}{f' and no {absent!r}' if absent else ''}; got {verdicts!r}")

    def without(recs, harness, cell, case):
        return [r for r in recs if (r.harness, r.cell, r.case) != (harness, cell, case)]

    full = [rec(c, case, h, "pass", i) for c, case in PARITY_KEYS for h in HARNESSES for i in range(3)]
    parity("three passing runs of every case", full, "OpenAI parity: met")
    parity("three passing runs of every case", full, "Anthropic parity: met")
    worse = without(full, "nanocode-openai", "E2", "pr") + [
        rec("E2", "pr", "nanocode-openai", o, i) for i, o in enumerate(("pass", "pass", "fail"))
    ]
    parity("fewer nanocode passes", worse, "OpenAI parity: not met — nanocode-openai passes fewer counted runs than codex-stock: E2 pr")
    parity("fewer nanocode passes in the other pair", worse, "Anthropic parity: met")
    worse_a = without(full, "nanocode-anthropic", "E1", "seeded-pr") + [
        rec("E1", "seeded-pr", "nanocode-anthropic", o, i) for i, o in enumerate(("pass", "fail", "pass"))
    ]
    parity(
        "fewer nanocode-anthropic passes",
        worse_a,
        "Anthropic parity: not met — nanocode-anthropic passes fewer counted runs than claude-agent-acp: E1 seeded-pr",
    )
    # A pair compares only its own harnesses: nanocode-openai at 2 of 3 passes against a
    # claude-agent-acp at 1 of 3 does not meet the OpenAI pair, whose codex-stock passes 3.
    cross = [r for r in worse if (r.harness, r.cell, r.case) != ("claude-agent-acp", "E2", "pr")] + [
        rec("E2", "pr", "claude-agent-acp", o, i) for i, o in enumerate(("pass", "fail", "fail"))
    ]
    parity("across pairs", cross, "OpenAI parity: not met — nanocode-openai passes fewer counted runs than codex-stock: E2 pr")
    parity("across pairs", cross, "Anthropic parity: met")
    openai_only = [r for r in full if PAIR_OF[r.harness].name == "OpenAI"]
    parity("one pair run", openai_only, "OpenAI parity: met")
    parity("one pair run", openai_only, "Anthropic parity: not yet run.")
    voided = without(full, "codex-stock", "E1", "seeded-pr") + [
        rec("E1", "seeded-pr", "codex-stock", o, i) for i, o in enumerate(("pass", "pass", "void"))
    ]
    parity("a void run", voided, f"fewer than {PARITY_RUNS} counted runs: codex-stock E1 seeded-pr")
    one_case = without(full, "nanocode-openai", "E1", "public-pr") + [
        rec("E1", "seeded-pr", "nanocode-openai", "pass", i) for i in range(3, 6)
    ]
    parity("runs of one case standing in for another", one_case, "fewer than 3 counted runs: nanocode-openai E1 public-pr")
    mismatch = [r for r in full if r.cell != "E2"] + [rec("E2", "mismatch", h, "pass", i) for h in HARNESSES for i in range(3)]
    parity("the E2 mismatch cell", mismatch, "fewer than 3 counted runs: codex-stock E2 pr; nanocode-openai E2 pr")
    # Only the FIRST three count: later passes do not lift an early fail, later fails do
    # not sink three early passes.
    late_pass = without(full, "nanocode-openai", "E2", "pr") + [
        rec("E2", "pr", "nanocode-openai", o, i) for i, o in enumerate(("fail", "pass", "pass", "pass", "pass", "pass"))
    ]
    parity("later passes after an early fail", late_pass, "nanocode-openai passes fewer counted runs than codex-stock: E2 pr")
    late_fail = full + [rec("E2", "pr", "nanocode-openai", "fail", i) for i in range(3, 6)]
    parity("later fails after three passes", late_fail, "OpenAI parity: met")
    if "3 pass of 3 (+3 not counted)" not in render_parity(late_fail):
        failures.append("parity does not show the runs it did not count")
    if "3 pass of 3 (1 void)" not in render_parity(voided + [rec("E1", "seeded-pr", "codex-stock", "pass", 3)]):
        failures.append("parity does not show the void runs it skipped")

    # 6b. The counted round, refused across records: every E1/E2 parity run on one
    #     kata_sha (both pairs), and each E1 case's first three non-void runs on a harness
    #     submitted through the CLI or REST, with both among them once no later run can
    #     add the missing one.
    def round_check(label, runs, needle):
        if needle:
            refusals.append(label)
        with tempfile.TemporaryDirectory(prefix="evidence-page-") as tmp:
            root = _mk_root(tmp)
            for run in runs:
                d, contents = run if isinstance(run, tuple) else (run, None)
                _write_run(os.path.join(root, RUNS), d, **({"files": (), "contents": contents} if contents else {}))
            rc, err = _quiet(True, root)
            if (rc, needle) == (0, None) or (rc == 1 and needle and needle in err):
                return
            want = f"a refusal naming {needle!r}" if needle else "no round refusal"
            failures.append(f"{label}: rc={rc}, want {want}; got {err.strip()!r}")

    def run_at(i, **changes):
        surface = changes.get("surface", "cli")
        auth = {"api_auth": "signed-token"} if surface in ("rest", "mcp") else {}
        return edit(**{"started_utc": f"2026-11-01T12:{i:02}:00Z", **auth, **changes})

    codex_run = {"harness": "codex-stock", "capsule_network": "vendor-egress-only", "vendor_version": "codex-cli 0.165.0"}
    round_check(
        "a round on two kata_shas, in one pair",
        [run_at(0, kata_sha="d" * 40), run_at(1, **codex_run)],
        "the counted round mixes kata_sha",
    )
    round_check(
        "a round on two kata_shas, across the pairs",
        [run_at(0, kata_sha="d" * 40), run_at(1, **acp)],
        "the counted round mixes kata_sha",
    )
    round_check(
        "a void parity run on another kata_sha",
        [run_at(0), run_at(1, case="public-pr", outcome="void", void_reason="oracles.txt: x", kata_sha="d" * 40)],
        "the counted round mixes kata_sha",
    )
    round_check(
        "E2 mismatch and E3 on another kata_sha",
        [
            run_at(0),
            (run_at(1, cell="E2", case="mismatch", kata_sha="d" * 40, **ELSEWHERE), {"oracle.txt": "x\n"}),
            (run_at(2, cell="E3", case="P1", settlement="proven-ambiguous", unknown_charges=0, kata_sha="e" * 40, **ELSEWHERE),
             {"oracle.txt": "x\n"}),
        ],
        None,
    )
    round_check(
        "three counted E1 runs with no REST run",
        [run_at(i) for i in range(3)],
        "nanocode-openai E1 seeded-pr: the first 3 non-void runs lack a rest run",
    )
    round_check(
        "a later REST run does not repair the first three",
        [run_at(i) for i in range(3)] + [run_at(3, surface="rest")],
        "nanocode-openai E1 seeded-pr: the first 3 non-void runs lack a rest run",
    )
    round_check(
        "a void REST run replaced on the CLI",
        [run_at(0), run_at(1, surface="rest", outcome="void", void_reason="oracles.txt: x"), run_at(2), run_at(3)],
        "nanocode-openai E1 seeded-pr: the first 3 non-void runs lack a rest run",
    )
    round_check(
        "a void REST run replaced on REST",
        [run_at(0), run_at(1, surface="rest", outcome="void", void_reason="oracles.txt: x"), run_at(2), run_at(3, surface="rest")],
        None,
    )
    round_check("two CLI runs so far", [run_at(0), run_at(1)], None)
    # The mix is the refusal; the order and the void run's replacement surface are the
    # procedure the runs follow, so a counted set that holds both surfaces is accepted.
    round_check("counted runs in the order rest, cli, cli", [run_at(0, surface="rest"), run_at(1), run_at(2)], None)
    round_check(
        "a void CLI run replaced on REST, the mix holding",
        [run_at(0, outcome="void", void_reason="oracles.txt: x"), run_at(1, surface="rest"), run_at(2, surface="rest"), run_at(3)],
        None,
    )
    round_check(
        "a counted E1 run through MCP",
        [run_at(0, surface="mcp")],
        "nanocode-openai E1 seeded-pr: counted run e1-seeded-pr-nanocode-openai-20261101T120000Z is submitted through mcp",
    )
    def e2_at(i, **changes):
        surface = changes.get("surface", "cli")
        auth = {"api_auth": "signed-token"} if surface in ("rest", "mcp") else {}
        return e2(**{"started_utc": f"2026-11-01T13:{i:02}:00Z", **auth, **changes})

    round_check("an E2 run through REST", [e2_at(i, surface=("rest", "mcp", "cli")[i]) for i in range(3)], None)
    # One task variant across every counted E2 pr run, of both pairs; `refined` is never
    # compared, and a void run, a run after the first three or a refine run is outside it.
    round_check(
        "counted E2 pr runs differ in variant, in one pair",
        [e2_at(0), e2_at(1, **codex_run, variant="task-only")],
        "the counted E2 pr runs differ in variant",
    )
    round_check(
        "counted E2 pr runs differ in variant, across the pairs",
        [e2_at(0), e2_at(1, **acp, variant="task-only")],
        "the counted E2 pr runs differ in variant",
    )
    round_check("counted E2 pr runs differ in refined", [e2_at(0), e2_at(1, **codex_run, refined="yes")], None)
    round_check(
        "a void E2 pr run on another variant",
        [e2_at(0), e2_at(1, variant="task-only", outcome="void", void_reason="pr.json: x")],
        None,
    )
    round_check("a fourth E2 pr run, after the first three, on another variant", [e2_at(i) for i in range(3)] + [e2_at(3, variant="task-only")], None)
    round_check("the refine cell beside the counted pr runs", [e2_at(0), e2_at(1, case="refine")], None)
    # The refine cell runs in the counted round, on its one pinned commit, of any outcome.
    round_check(
        "a refine run on another kata_sha",
        [e2_at(0), e2_at(1, case="refine", kata_sha="d" * 40)],
        "the counted round mixes kata_sha",
    )
    round_check(
        "a void refine run on another kata_sha",
        [e2_at(0), e2_at(1, case="refine", outcome="void", void_reason="pr.json: x", kata_sha="d" * 40)],
        "the counted round mixes kata_sha",
    )

    # 7. In the archive (its root commit is an ancestor of HEAD), `kata_sha` is an ancestor
    #    of HEAD and `kata_tree` its tree; outside it (the public squash, a tarball, a
    #    repository without the archive's root) only their shape is checked.
    def provenance(label, changes, needle, archive=True):
        refusals.append(label)
        with tempfile.TemporaryDirectory(prefix="evidence-page-") as tmp:
            root = _mk_root(tmp)
            first, tested, tree, side = _archive(root)
            known = {"tested": tested, "tree": tree, "side": side}
            d = edit(**{k: known.get(v, v) for k, v in changes.items()})
            _write_run(os.path.join(root, RUNS), d)
            rc, err = _quiet(True, root, archive_root=first if archive else "f" * 40)
            if (rc, needle) == (0, None) or (rc == 1 and needle and needle in err):
                return
            failures.append(f"{label}: rc={rc}, want {'a refusal naming ' + repr(needle) if needle else 'acceptance'}; got {err.strip()!r}")

    provenance("archive record", {"kata_sha": "tested", "kata_tree": "tree"}, None)
    provenance("non-ancestor kata_sha", {"kata_sha": "side", "kata_tree": "tree"}, "is not an ancestor of HEAD")
    provenance("unknown kata_sha", {"kata_sha": "d" * 40, "kata_tree": "tree"}, "is not an ancestor of HEAD")
    provenance("kata_tree not kata_sha's tree", {"kata_sha": "tested", "kata_tree": "e" * 40}, "is not the tree of `kata_sha`")
    provenance("outside the archive", {"kata_sha": "d" * 40, "kata_tree": "e" * 40}, None, archive=False)

    # 8. The reviewer's parity probe: six nanocode-openai runs per cell at three passes
    #    against three codex-stock runs per cell at three passes. (Its other half, the two
    #    harnesses on different models, is a record refusal now: each record holds its
    #    pair's model.)
    probe = []
    for c in PARITY_CASES:
        case = PARITY_CASES[c][0]
        probe += [rec(c, case, "nanocode-openai", o, i) for i, o in enumerate(("pass", "fail", "pass", "fail", "pass", "fail"))]
        probe += [rec(c, case, "codex-stock", "pass", i) for i in range(3)]
    if "OpenAI parity: met" in render_parity(probe):
        failures.append("the reviewer's probe (3 of 6 nanocode passes) reads parity met")

    # 9. PRICED's current harnesses are exactly those whose AdapterKind `billing_backend`
    #    prices, read from the engine's source, not from this script.
    with open(os.path.join(ROOT, AGENT_RS), encoding="utf-8") as fh:
        kinds = priced_adapter_kinds(fh.read())
    if kinds is None:
        failures.append(f"cannot read `AdapterKind::billing_backend` in {AGENT_RS}: PRICED is unchecked")
    elif {h for h, k in ADAPTER_KIND.items() if k in kinds} != set(PRICED) - set(HISTORICAL_PRICED):
        failures.append(
            f"PRICED {sorted(PRICED)} is not the harnesses `billing_backend` prices ({sorted(kinds)}): "
            "move PRICED, the README's Spend rule and the priced-* cells together"
        )

    if failures:
        print("evidence-page self-test: FAIL", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(
        "evidence-page self-test: PASS (valid record rendered and checked; an unbacked page "
        f"row, a missing fence and {len(refusals)} planted invalid records refused; empty state "
        "reads not yet run; parity counts proven)"
    )
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("cmd", nargs="?", choices=("check", "render"))
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.cmd is None:
        parser.print_help(sys.stderr)
        return 2
    return cmd(write=args.cmd == "render")


if __name__ == "__main__":
    sys.exit(main())
