"""ledger.py: read an E1/E2 run's outcome out of kata's database, from outside kata.

    python3 -I ledger.py DATA_DIR execs [WORKFLOW]
    python3 -I ledger.py DATA_DIR head EXEC
    python3 -I ledger.py DATA_DIR stages EXEC
    python3 -I ledger.py DATA_DIR turns EXEC
    python3 -I ledger.py DATA_DIR iterations EXEC
    python3 -I ledger.py DATA_DIR record EXEC
    python3 -I ledger.py DATA_DIR turncheck EXEC MODEL HARNESS
    python3 -I ledger.py DATA_DIR params EXEC
    python3 -I ledger.py DATA_DIR variant EXEC
    python3 -I ledger.py DATA_DIR refined EXEC
    python3 -I ledger.py DATA_DIR refinecheck EXEC TEST_COMMAND
    python3 -I ledger.py --leakscan [--tree] FILE...
    python3 -I ledger.py --self-test

DATA_DIR is the node's data directory (`<clone>/.kata/data`); EXEC is an
execution id as kata prints it (a 26-character ULID). Every read goes through
a SECOND, read-only SQLite handle (`mode=ro` on `operational.db` and
`cas.db`); nothing here asks kata. Run it after `kata run wait EXEC`: a
non-terminal execution is refused (exit 3), so no oracle reads a run mid-flight.

  execs       one row per execution, oldest first: id, workflow, created (UTC),
              state. Optionally only WORKFLOW's.
  head        the frozen target: the invocation's target spec, its frozen head
              commit and the work tree's base commit (the head row with the
              lowest head_seq).
  stages      one row per worker attempt of every AGENT stage: ordinal, state,
              accepted, adapter, the requested model/effort, model_reported,
              schema_sent, the charge's source, `provider_failure` (on a
              failed attempt's charge, the class its terminal transition
              records, `refused` or `transient`, schema 44; `-` otherwise),
              the four token counters and the cost; then one
              total per stage over EVERY attempt, failed ones included (a
              failed, cancelled or orphaned attempt's charge is the
              `terminal_charge` its terminal transition carries).
              A charge whose cost is `Unavailable` with zero counters is
              unmeasured (`StageUsage::unmetered` under the adapter label, or
              an unknown answer's empty backend): its tokens and cost print
              `unknown`, never 0. `retries` counts attempts beyond one
              per occurrence (a loop member's iterations are occurrences, not
              retries). So does a terminal attempt whose
              transitions carry no charge at all (charge `unrecorded`: a
              performed-but-failed adoption, e.g. work_delta_out_of_scope,
              records only its reason). Any unknown attempt makes the stage
              total `unknown` too (its known part is printed beside it).
  turns       per agent attempt, its session evidence (the Private CAS blob the
              completion names): codex's TokenUsageFrame folds
              (metered/reemitted/unmetered), the metered `last` sum against
              the final frame's thread `total`, TurnAnswer source/phase/
              items_view, every ModelRerouted frame, events_dropped, and a
              count of every other event kind.
  iterations  one row per iteration of the `test` stage's fix loop: attempts,
              the accepted attempt's ordinal and its TestReport.status. The
              iteration is the second-to-last coordinate of the occurrence's
              operation path (u64 LE count, then u32 LE coordinates).
  record      the run record's spend lines over every agent stage:
              `tokens_recorded` = the known part (every measured charge,
              failed attempts' included) and `unmetered_calls` = the number of
              unknown charges (`stages`' unknown_charges summed), so a run
              whose oracles pass still has a valid record when a call's usage
              is unknown, and that call is never stated as 0. Then
              `cost_recorded` (and `cost_recorded_usd`), read-only from
              kata's own charges: `"estimated"` with the sum of every
              charge's micro_usd (failed attempts' included) exactly when
              every agent attempt ran on an adapter of a harness in PRICED
              (scripts/evidence-page.py `PRICED` at e2942e163: codex-stock's
              codex_app_server and nanocode-anthropic's nanocode_anthropic)
              and EVERY charge is kata's `Estimated`; else `"unavailable"`
              with no `cost_recorded_usd` (an unpriced adapter, an
              `Unavailable` charge such as a subscription turn's
              `unavailable(codex)`, or any unknown charge, whose cost a
              partial sum would understate), with the reason as a `#` line.
              kata's authoritative 0 (zero counters, `Authoritative`
              micro_usd 0: a failure that billed nothing, e.g. a nanocode
              turn its provider refused, PROVEN NOT PERFORMED) is a KNOWN
              zero: it adds nothing to tokens_recorded, is no unmetered
              call, and leaves the cost to the other charges (`unavailable`
              when it is the only kind). It refuses (exit 3) an `Estimated`
              charge on an adapter PRICED does not admit and every other
              `Authoritative` one (no record value states it): kata's
              pricing then differs from the page's, and the page must be
              re-read before any record is written.
  turncheck   the per-harness precondition turn (RUNBOOK §P(c)): PASS/FAIL for
              terminal-completed, model-reported, tokens-known (no unknown
              charge and a non-zero known part), no-unmetered-frame,
              no-reroute. Exit 1 on any FAIL. HARNESS is one of
              harness-config.py's HARNESSES and MODEL is that harness's
              PINNED_MODEL (prelude.sh's $MODEL); anything else is refused
              before the ledger is read (exit 3), so the alias below is never
              accepted against a MODEL the operator chose.
              model-reported passes when there is a completed attempt and
              EVERY completed attempt's model_reported is MODEL, or is the one
              value harness-config.py's PICKER_ANSWERS holds for (HARNESS,
              that attempt's adapter, MODEL) on an attempt that declared MODEL:
              today only claude-agent-acp's `sonnet`, its measured picker
              answer to kata's write of claude-sonnet-5-5 under generic_acp.
              It refuses: no completed attempt, a missing model_reported, and
              any other value, that alias on any other harness, adapter or
              declared model included. It does not refuse a claude-agent-acp
              build other than the measured 0.79.0 that answers `sonnet` too:
              the vendor pin is §2's (pin-check, harness-config.py).
  params      one row per invocation param: name, bytes, sha256 (never the
              value: the refine cell's `gate_suite` is held out).
  variant     the E2 task variant, read from the invocation's `task` param and
              compared (trailing newlines aside: `$(cat ...)` strips them) with
              this kit's texts: `task-only` (task.md), `refine-addendum`
              (task.md + refine-addendum.md), `refine-cell` (task.md +
              refine-cell.md), else `unknown`. Prints `variant = "<v>"`.
  refined     the OBSERVED fix-loop outcome: `refined = "yes"` when test#iter-0
              failed and a later iteration ran (the loop refined at least
              once), else "no"; plus `iterations` and `final_test` (the last
              iteration's TestReport status). A parity E2 run records it; only
              the refine cell makes it a pass condition.
  refinecheck the E2 refine cell's own oracles (RUNBOOK §4b): PASS/FAIL for
              variant (refine-cell), gate-bound (the `gate_suite` param is
              this kit's gate/align-gate.sh and `test_command` is
              TEST_COMMAND, byte for byte), gate-unseen (no agent attempt's
              prompt holds the gate's SOURCE in a form `gate_leaks` names, and
              at least one prompt was read), refined, final-gate (the last iteration
              passed and the LAST gate summary in its feedback is exactly
              `linekit-gate: N passed, 0 failed, N checks` with N the number of
              checks gate/align-gate.sh declares, 25: `gate_all_pass`), and
              two info lines: `refine_cause` (which of the repository suite and
              the gate failed at iteration 0) and `iter0_gate_fails` (the gate
              checks iteration 0's feedback names as failed: C<n>-... house
              conventions, G<n>-... functional). Exit 1 on any FAIL.

  --leakscan  no database: each FILE's text (for a FILE ending .tar, each
              member that is a regular file, a hard link or a symbolic link,
              a symlink's text being its target, as git stores it) through
              `gate_leaks` (below); with --tree also any LITERAL naming of
              the gate's capsule path `linekit-gate.sh`, in a text or in a
              member's path (a path assembled at run time is not refused).
              One `leak TEXT: ...` line per hit, then `leakscan: N text(s)
              scanned, M with a leak`, N counting what was READ (a plain FILE
              is one text, a .tar FILE one per member of those three kinds),
              never the argument count; exit 1 when M > 0. e2-oracles.sh runs it over
              the fresh clone's tracked files (`gate-unnamed`: it requires
              N >= 1 and M = 0), prove.sh over the dry run's feedback (a leaky
              candidate must be named, every honest one must not).

gate_leaks refuses EXACTLY these forms of gate/align-gate.sh's source in a
text, after both are sanitised as change.star sanitises feedback (every byte
outside printable ASCII, `\\` and `"` become a space) and every whitespace run
is collapsed to one space: (1) the marker `KATA-E2-GATE-SOURCE`; (2) a case
call, `t G<n>-`, `te G<n>-` or `conv C<n>-` (the gate prints `FAIL G<n>-...`
and `FAIL C<n>-...`, never those);
(3) a definition of one of the gate's shell functions, `name() {`; (4) any
whole source line of 30 characters or more. It does NOT refuse a fragment
shorter than a line, nor an encoded or paraphrased copy: the gate's text is
readable by every process of the test stage, candidate code included
(RUNBOOK §4b), so this is detection of a verbatim leak, not containment.

Exit 0 on a printed answer, 2 on usage, 3 on a refused read (unknown
execution, non-terminal execution, a missing blob).
"""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
KIT = os.path.dirname(os.path.abspath(__file__))
GATE_MARKER = "KATA-E2-GATE-SOURCE"
VARIANTS = (("task-only", ("task.md",)), ("refine-addendum", ("task.md", "refine-addendum.md")),
            ("refine-cell", ("task.md", "refine-cell.md")))
TERMINAL = {"completed", "failed", "cancelled"}
TOKEN_KEYS = ("input", "output", "cache_read", "cache_write")
# The harnesses an evidence record may state a priced cost for: scripts/evidence-page.py
# `PRICED` at e2942e163 (kata's `AdapterKind::billing_backend` is Some only for
# codex_app_server and nanocode_anthropic). `record` maps each to the adapter it runs as
# through harness-config.py's agent_block (priced_adapters); the self-test pins both.
PRICED = ("codex-stock", "nanocode-anthropic")


class Refused(Exception):
    pass


def ulid_text(raw):
    n = int.from_bytes(raw, "big")
    return "".join(CROCKFORD[(n >> (5 * i)) & 31] for i in range(25, -1, -1))


def ulid_bytes(text):
    if len(text) != 26:
        raise Refused(f"`{text}` is not a 26-character execution id")
    n = 0
    for ch in text.upper():
        k = CROCKFORD.find(ch)
        if k < 0:
            raise Refused(f"`{text}` is not a ULID (character {ch!r})")
        n = n * 32 + k
    if n >> 128:
        raise Refused(f"`{text}` overflows 128 bits")
    return n.to_bytes(16, "big")


def connect(data_dir):
    op = os.path.join(data_dir, "operational.db")
    cas = os.path.join(data_dir, "cas.db")
    for path in (op, cas):
        if not os.path.isfile(path):
            raise Refused(f"no {path}")
    conn = sqlite3.connect(f"file:{op}?mode=ro", uri=True)
    conn.execute("ATTACH DATABASE ? AS cas", (f"file:{cas}?mode=ro",))
    return conn


def jtext(blob):
    return json.loads(bytes(blob).decode() if isinstance(blob, (bytes, memoryview)) else blob)


def execution(conn, text, need_terminal=True):
    raw = ulid_bytes(text)
    row = conn.execute(
        "select json_extract(cast(p.program_json as text), '$.workflow_name'), e.state "
        "from programs p left join execution_projection e using (execution_id) "
        "where p.execution_id = ?", (raw,)).fetchone()
    if row is None:
        raise Refused(f"no execution {text} in this data dir")
    if need_terminal and row[1] not in TERMINAL:
        raise Refused(f"execution {text} is `{row[1]}`, not terminal: run `kata run wait {text} "
                      "--timeout-secs 7200` first")
    return raw, row[0], row[1]


def cas_json(conn, object_hex):
    row = conn.execute("select storage, blob, size from cas.cas_objects where object_id = unhex(?)",
                       (object_hex,)).fetchone()
    if row is None:
        raise Refused(f"no CAS object {object_hex}")
    if row[0] != "inline":
        raise Refused(f"CAS object {object_hex} is stored as a file ({row[2]} bytes); read it under "
                      "the data dir's CAS file store")
    return jtext(row[1])


def table(rows, header):
    cells = [header] + [["" if v is None else str(v) for v in r] for r in rows]
    width = [max(len(r[i]) for r in cells) for i in range(len(header))]
    out = []
    for k, r in enumerate(cells):
        out.append("  ".join(v.ljust(width[i]) for i, v in enumerate(r)).rstrip())
        if k == 0:
            out.append("  ".join("-" * w for w in width))
    return "\n".join(out)


# --- execs ------------------------------------------------------------------

def cmd_execs(conn, workflow=None):
    rows = []
    for raw, name, created, state in conn.execute(
            "select p.execution_id, json_extract(cast(p.program_json as text), '$.workflow_name'), "
            "p.created_at_ms, e.state from programs p left join execution_projection e "
            "using (execution_id) order by p.created_at_ms"):
        if workflow and name != workflow:
            continue
        when = datetime.fromtimestamp(created / 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        rows.append([ulid_text(raw), name, when, state])
    return table(rows, ["execution", "workflow", "created_utc", "state"])


# --- head -------------------------------------------------------------------

def cmd_head(conn, text):
    raw, _, _ = execution(conn, text)
    inv = conn.execute("select cast(invocation_json as text) from invocations where execution_id = ?",
                       (raw,)).fetchone()
    target = jtext(inv[0]).get("target") if inv else None
    head = conn.execute("select base_commit, head_seq, branch from execution_work_tree_heads "
                        "where execution_id = ? order by head_seq limit 1", (raw,)).fetchone()
    spec = None if target is None else target.get("spec")
    frozen = None if target is None else (target.get("head") or {}).get("commit")
    lines = [f"execution    {text}",
             f"target_spec  {json.dumps(spec, sort_keys=True)}",
             f"frozen_head  {frozen}",
             f"base_commit  {None if head is None else head[0]}   (head_seq {None if head is None else head[1]}, branch {None if head is None else head[2]})"]
    if target and target.get("compare"):
        lines.append(f"merge_base   {target['compare'].get('merge_base')}")
    return "\n".join(lines)


# --- stages -----------------------------------------------------------------

def unmeasured(usage, adapter):
    """An unmeasured charge: `Unavailable` with zero counters.

    `StageUsage::unmetered` writes zero counters beside `Unavailable` naming the
    adapter label (a completion whose vendor reported no parseable usage), and a
    turn whose answer is unknown carries `Unavailable` with an EMPTY backend
    (measured at w6d: an EOF after turn/start). A measured turn is never zero:
    kata's own `meter_call` turns a zero usage into `Unavailable` too. So zero
    counters under `Unavailable`, whatever the backend, are unknown, never 0. A
    subscription turn kata measured keeps its counters under `Unavailable(codex)`.
    """
    cost = usage.get("cost") or {}
    return cost.get("quality") == "unavailable" and all((usage.get(k) or 0) == 0 for k in TOKEN_KEYS)


def billed_nothing(usage):
    """kata's authoritative 0: `StageUsage::unbilled()`, zero counters beside `Authoritative`
    with `micro_usd` 0. The main records it on a worker failure that carried no usage, a refusal
    that proves no billable call ran (worker_loop.rs), e.g. a nanocode turn its model provider
    refused before billing anything (`FailedTurnCharge::Nothing`, PROVEN NOT PERFORMED, beside
    its `provider_failure` class; 34d5c77c8). A KNOWN zero (`StageUsage::recorded_tokens` is
    Some(0)), never unknown; any other `Authoritative` charge is not this shape."""
    cost = usage.get("cost") or {}
    micro = cost.get("micro_usd")
    return (cost.get("quality") == "authoritative" and micro == 0 and not isinstance(micro, bool)
            and all((usage.get(k) or 0) == 0 for k in TOKEN_KEYS))


def cost_text(usage, adapter):
    if usage is None:
        return "unknown"
    if unmeasured(usage, adapter):
        return "unknown"
    cost = usage.get("cost") or {}
    q = cost.get("quality")
    if q == "unavailable":
        return f"unavailable({cost.get('backend')})"
    if q in ("estimated", "authoritative"):
        return f"{q}:{cost.get('micro_usd', 0) / 1e6:.6f}USD"
    return f"?{json.dumps(cost, sort_keys=True)}"


def attempt_charges(conn, attempt_id):
    """(completed output usage, [terminal charge usages], output, final state) of one attempt."""
    completed, terminal, output = None, [], None
    for state, payload in conn.execute(
            "select resulting_state, cast(payload_json as text) from transitions "
            "where attempt_id = ? order by seq", (attempt_id,)):
        p = json.loads(payload)
        out = p.get("output")
        if state == "completed" and isinstance(out, dict):
            output = out
            if out.get("token_usage") is not None:
                completed = out["token_usage"]
        charge = p.get("terminal_charge")
        if isinstance(charge, dict) and charge.get("token_usage") is not None:
            terminal.append((state, charge["token_usage"]))
    return completed, terminal, output


def agent_attempts(conn, raw):
    rows = conn.execute(
        "select a.attempt_id, a.stage_id, a.attempt_ordinal, p.state, a.occurrence_id, "
        "(o.accepted_attempt_id = a.attempt_id), json_extract(cast(c.blob as text), '$.process') "
        "from attempts a "
        "join capsules k on k.capsule_id = unhex(json_extract(cast(a.assignment_json as text), '$.capsule.capsule.id')) "
        "join cas.cas_objects c on c.object_id = k.capsule_object_id "
        "join attempt_projection p on p.execution_id = a.execution_id and p.stage_id = a.stage_id "
        "  and p.attempt_ordinal = a.attempt_ordinal "
        "join occurrences o on o.occurrence_id = a.occurrence_id "
        "where a.execution_id = ? and a.executor = 'worker' "
        "order by a.stage_id, a.attempt_ordinal", (raw,)).fetchall()
    out = []
    for attempt_id, stage, ordinal, state, occurrence, accepted, process in rows:
        proc = json.loads(process) if process else {}
        if proc.get("kind") != "agent" and proc.get("adapter") is None:
            continue
        out.append((attempt_id, stage, ordinal, state, bool(accepted), proc, occurrence))
    return out


def provider_failure_of(conn, attempt_id):
    """The model provider's failure class (`refused`, `transient`) a failed attempt's terminal
    transition records beside its verdict (`provider_failure`, operational schema 44), or None
    when it records none (every failure but a provider-failed agent turn: `null`)."""
    found = None
    for (payload,) in conn.execute("select cast(payload_json as text) from transitions "
                                   "where attempt_id = ? order by seq", (attempt_id,)):
        found = json.loads(payload).get("provider_failure") or found
    return found


def charges_of(conn, attempt_id):
    """([(source, usage or None)], output) of one attempt: its completed charge and terminal
    charges, or one `unrecorded` charge (usage None) when its transitions carry none."""
    completed, terminal, output = attempt_charges(conn, attempt_id)
    charges = ([("completed", completed)] if completed is not None else []) + terminal
    # A terminal attempt whose transitions carry no charge at all: the turn may have spent (a
    # performed-but-failed adoption records only its reason), so its usage is unrecorded, never 0.
    return charges or [("unrecorded", None)], output


def stage_rows(conn, raw):
    """(rows, totals): one row per charge of every agent attempt, and per-stage totals."""
    rows, totals = [], {}
    for attempt_id, stage, ordinal, astate, accepted, proc, occurrence in agent_attempts(conn, raw):
        adapter = proc.get("adapter")
        charges, output = charges_of(conn, attempt_id)
        failure = provider_failure_of(conn, attempt_id)
        reported = ((output or {}).get("agent") or {}).get("model_reported")
        t = totals.setdefault(stage, {"attempts": 0, "occurrences": set(), "unknown": 0,
                                      **{k: 0 for k in TOKEN_KEYS}, "micro_usd": 0, "unavailable": 0})
        t["attempts"] += 1
        t["occurrences"].add(occurrence)
        for source, usage in charges:
            if usage is None or unmeasured(usage, adapter):
                counters = ["unknown"] * 4
                t["unknown"] += 1
            else:
                counters = [usage.get(k, 0) for k in TOKEN_KEYS]
                for k in TOKEN_KEYS:
                    t[k] += usage.get(k, 0) or 0
                cost = usage.get("cost") or {}
                if cost.get("quality") == "unavailable":
                    t["unavailable"] += 1
                else:
                    t["micro_usd"] += cost.get("micro_usd", 0) or 0
            rows.append([stage, ordinal, astate, int(accepted), adapter, proc.get("model") or "-",
                         proc.get("reasoning_effort") or "-", reported or "-",
                         int(proc.get("output_schema") is not None), source,
                         (failure if source != "completed" else None) or "-", *counters,
                         cost_text(usage, adapter)])
    return rows, totals


def cmd_stages(conn, text):
    raw, _, state = execution(conn, text)
    rows, totals = stage_rows(conn, raw)
    head = ["stage", "ordinal", "state", "accepted", "adapter", "model", "effort", "model_reported",
            "schema_sent", "charge", "provider_failure", "input", "output", "cache_read", "cache_write",
            "cost"]
    lines = [f"execution {text} ({state})", table(rows, head), "", "stage totals (every attempt):"]
    trows = []
    for stage, t in sorted(totals.items()):
        known = [t[k] for k in TOKEN_KEYS]
        if t["unknown"]:
            counters = [f"unknown(known part {v})" for v in known]
            cost = "unknown"
        else:
            counters = known
            cost = "unavailable" if t["unavailable"] else f"{t['micro_usd'] / 1e6:.6f}USD"
        # A loop member runs one occurrence per iteration; a retry is a further attempt
        # at the SAME occurrence.
        trows.append([stage, t["attempts"], len(t["occurrences"]), t["attempts"] - len(t["occurrences"]),
                      t["unknown"], *counters, cost])
    lines.append(table(trows, ["stage", "attempts", "occurrences", "retries", "unknown_charges", "input",
                               "output", "cache_read", "cache_write", "cost"]))
    return "\n".join(lines)


def record_fields(totals):
    """The run record's spend fields over every agent stage of one execution.

    `tokens_recorded` is the KNOWN part (every charge kata measured, failed
    attempts' terminal charges included); `unmetered_calls` counts the charges
    whose usage is unknown (an unmeasured charge, or a terminal attempt with no
    charge at all), which docs/evidence/README.md records beside the total
    rather than as 0. The record keeps the two apart, so a pass never states an
    unknown call as zero spend and never hides one.
    """
    known = {k: sum(t[k] for t in totals.values()) for k in TOKEN_KEYS}
    unknown = sum(t["unknown"] for t in totals.values())
    return known, unknown


def priced_adapters():
    """{adapter: harness} for each harness in PRICED, the adapter harness-config.py's
    agent_block runs it as."""
    hc = harness_config()
    out = {}
    for h in PRICED:
        (adapter,) = re.findall(r'^adapter = "([^"]*)"$', hc.agent_block(h, "<ca>"), re.M)
        out[adapter] = h
    return out


def cost_fields(charges, priced):
    """(cost_recorded, cost_recorded_usd or None, why) over CHARGES, one (adapter, usage or None)
    per charge of every agent attempt, PRICED being priced_adapters().

    `estimated` with the sum of the charges' micro_usd exactly when there is an `Estimated` charge
    and every other one is too (so on a PRICED adapter) or is kata's authoritative 0
    (`billed_nothing`: a known zero, which adds nothing to the sum and never makes the cost
    unavailable); otherwise `unavailable`. Refused: an `Estimated` charge on any other adapter,
    every `Authoritative` charge but the authoritative 0 (a price, or tokens beside the 0), an
    `Estimated` charge with no integer micro_usd, and a cost quality kata does not write."""
    for adapter, usage in charges:
        cost = (usage or {}).get("cost") or {}
        q = cost.get("quality")
        if usage is not None and q not in ("estimated", "unavailable") and not billed_nothing(usage):
            raise Refused(f"a {adapter} charge has cost {json.dumps(cost, sort_keys=True)}: an evidence record "
                          "states only `estimated` or `unavailable` (evidence-page.py COST_RECORDED), and "
                          "admits only kata's authoritative 0 (zero counters, micro_usd 0) beside them")
        if q == "estimated" and adapter not in priced:
            raise Refused(f"kata priced a {adapter} charge, but evidence-page.py PRICED at e2942e163 admits a "
                          f"priced cost only on {', '.join(f'{h} ({a})' for a, h in sorted(priced.items()))}: "
                          "re-read the page at the pinned commit")
        if q == "estimated" and (isinstance(cost.get("micro_usd"), bool) or not isinstance(cost.get("micro_usd"), int)):
            raise Refused(f"an estimated {adapter} charge has no integer micro_usd: {json.dumps(cost, sort_keys=True)}")
    if not charges:
        return "unavailable", None, "no agent charge"
    unknown = sum(1 for a, u in charges if u is None or unmeasured(u, a))
    if unknown:
        return "unavailable", None, (f"{unknown} charge(s) of unknown usage: a sum of the rest would "
                                     "understate the run's cost")
    # Every charge is now Estimated (on a PRICED adapter: refused above otherwise), Unavailable
    # with its tokens (a subscription turn, or a turn on an adapter kata prices no turn of), or
    # kata's authoritative 0 (a call that billed nothing), which is neither.
    zero = sum(1 for _, u in charges if billed_nothing(u))
    priced_charges = [(a, u) for a, u in charges if not billed_nothing(u)]
    unavailable = sorted({f"{a} unavailable({u['cost'].get('backend')})" for a, u in priced_charges
                          if u["cost"]["quality"] == "unavailable"})
    if unavailable:
        return "unavailable", None, ("kata priced no turn of " + ", ".join(unavailable) + " (PRICED: "
                                     + ", ".join(sorted(priced.values())) + "; a subscription login meters no price)")
    if not priced_charges:
        return "unavailable", None, (f"no charge kata estimated: each of the {zero} charge(s) billed nothing "
                                     "(kata's authoritative 0)")
    micro = sum(u["cost"]["micro_usd"] for _, u in priced_charges)
    return "estimated", micro, (f"the sum of {len(priced_charges)} estimated charge(s), kata's own"
                                + (f", beside {zero} that billed nothing (kata's authoritative 0)" if zero else ""))


def cmd_record(conn, text):
    raw, _, state = execution(conn, text)
    _, totals = stage_rows(conn, raw)
    known, unknown = record_fields(totals)
    charges = [(proc.get("adapter"), usage)
               for attempt_id, _, _, _, _, proc, _ in agent_attempts(conn, raw)
               for _, usage in charges_of(conn, attempt_id)[0]]
    cost, micro, why = cost_fields(charges, priced_adapters())
    order = ("input", "cache_read", "cache_write", "output")
    return (f"# execution {text} ({state}): ledger.py record\n"
            "tokens_recorded = { " + ", ".join(f"{k} = {known[k]}" for k in order) + " }\n"
            f"unmetered_calls = {unknown}\n"
            f"# cost_recorded: {why}\n"
            f'cost_recorded = "{cost}"'
            + ("" if micro is None else f"\ncost_recorded_usd = {micro / 1e6:.6f}"))


def harness_config():
    """This kit's harness-config.py as a module: the per-harness pins and vendor knowledge live
    there, beside the harness blocks they were measured on."""
    spec = importlib.util.spec_from_file_location("harness_config", os.path.join(KIT, "harness-config.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def harness_table():
    """(HARNESSES, PICKER_ANSWERS, PINNED_MODEL), read from harness-config.py."""
    mod = harness_config()
    return mod.HARNESSES, mod.PICKER_ANSWERS, mod.PINNED_MODEL


def model_reported_ok(harness, adapter, declared, reported, pin, answers):
    """(ok, how) for one completed attempt's `model_reported` under turncheck's pin. OK when it IS
    the pin, or when it is the vendor's answer ANSWERS records for (HARNESS, ADAPTER, PIN) and the
    attempt DECLARED the pin (the answer is to kata's write of it); every other value is refused."""
    if reported == pin:
        return True, "exact"
    answer = answers.get(harness, {}).get((adapter, pin))
    if answer is not None and declared == pin and reported == answer[0]:
        return True, f"{reported} is {answer[1]}"
    return False, ""


def model_reported_check(harness, completed, pin, answers):
    """turncheck's model-reported over COMPLETED, one (adapter, declared model, model_reported) per
    completed attempt: (ok, detail, notes). OK only when there is a completed attempt and EVERY one
    passes model_reported_ok; NOTES are the accepted non-exact answers, for the PASS line."""
    judged = [model_reported_ok(harness, adapter, declared, reported, pin, answers)
              for adapter, declared, reported in completed]
    ok = bool(judged) and all(j for j, _ in judged)
    reported = sorted({r for _, _, r in completed})
    accepted = {f"{harness} {adapter}: {value}"
                for (adapter, declared), (value, _) in answers.get(harness, {}).items() if declared == pin}
    detail = (f"model_reported {reported or 'none (no completed attempt)'}, pin {pin} on {harness}"
              + (f" (also accepted: {'; '.join(sorted(accepted))}, on an attempt that declared {pin})"
                 if accepted else ""))
    notes = sorted({how for j, how in judged if j and how != "exact"})
    return ok, detail, notes


def cmd_turncheck(conn, text, model, harness):
    """The per-harness precondition turn (RUNBOOK §P(c)): PASS/FAIL lines."""
    harnesses, answers, pinned = harness_table()
    if harness not in harnesses:
        raise Refused(f"`{harness}` is not a harness ({', '.join(harnesses)})")
    if model != pinned[harness]:
        raise Refused(f"`{model}` is not {harness}'s pinned model ({pinned[harness]}, harness-config.py "
                      "PINNED_MODEL): turncheck judges a turn only against its harness's pin")
    raw, _, state = execution(conn, text)
    rows, totals = stage_rows(conn, raw)
    lines, fails = [], 0

    def check(label, ok, detail=""):
        nonlocal fails
        lines.append(("PASS " if ok else "FAIL ") + label + ("" if ok or not detail else ": " + detail))
        fails += 0 if ok else 1

    check("terminal-completed", state == "completed", f"state {state}")
    ok, detail, notes = model_reported_check(
        harness, [(r[4], r[5], r[7]) for r in rows if r[9] == "completed"], model, answers)
    check("model-reported", ok, detail)
    if ok and notes:
        lines[-1] += ": " + "; ".join(notes)
    _, unknown = record_fields(totals)
    known, _ = record_fields(totals)
    check("tokens-known", unknown == 0 and any(known.values()),
          f"{unknown} unknown charge(s), known part {known}")
    unmetered, reroutes = 0, []
    for attempt_id, *_ in agent_attempts(conn, raw):
        _, _, output = attempt_charges(conn, attempt_id)
        obj = ((output or {}).get("agent") or {}).get("session_evidence_object_id")
        if obj:
            folds, _, _, _, rr, _ = summarize_evidence(cas_json(conn, obj))
            unmetered += folds.get("unmetered", 0)
            reroutes += rr
    check("no-unmetered-frame", unmetered == 0, f"{unmetered} unmetered frame(s)")
    check("no-reroute", not reroutes, "; ".join(reroutes))
    lines.append(f"turncheck: {fails} failed")
    return "\n".join(lines), fails


# --- turns ------------------------------------------------------------------

def summarize_evidence(ev):
    events = ev.get("events", [])
    folds = {"metered": 0, "reemitted": 0, "unmetered": 0}
    metered = {}
    final_total = None
    first_total = None
    answers, reroutes, other = [], [], {}
    for e in events:
        kind = e.get("event")
        if kind == "token_usage_frame":
            folds[e.get("fold")] = folds.get(e.get("fold"), 0) + 1
            if first_total is None:
                first_total = e.get("total") or {}
            final_total = e.get("total") or {}
            if e.get("fold") == "metered":
                for k, v in (e.get("last") or {}).items():
                    metered[k] = metered.get(k, 0) + (v or 0)
        elif kind == "turn_answer":
            answers.append(f"source={e.get('source')} phase={e.get('phase')} items_view={e.get('items_view')}")
        elif kind == "model_rerouted":
            reroutes.append(f"{e.get('from_model')}->{e.get('to_model')} this_turn={e.get('this_turn')}")
        else:
            other[kind] = other.get(kind, 0) + 1
    return folds, metered, final_total, answers, reroutes, other


def cmd_turns(conn, text):
    raw, _, state = execution(conn, text)
    lines = [f"execution {text} ({state})"]
    for attempt_id, stage, ordinal, astate, accepted, proc, _ in agent_attempts(conn, raw):
        _, _, output = attempt_charges(conn, attempt_id)
        agent = (output or {}).get("agent") or {}
        lines.append(f"- {stage}#{ordinal} state={astate} accepted={int(accepted)} adapter={proc.get('adapter')} "
                     f"model={proc.get('model')} effort={proc.get('reasoning_effort')} "
                     f"model_reported={agent.get('model_reported')} stop_reason={agent.get('stop_reason')}")
        obj = agent.get("session_evidence_object_id")
        if not obj:
            lines.append("    session evidence: none on this attempt (no completed turn report)")
            continue
        ev = cas_json(conn, obj)
        folds, metered, final_total, answers, reroutes, other = summarize_evidence(ev)
        n = sum(folds.values())
        lines.append(f"    usage frames: {n} (metered {folds['metered']}, reemitted {folds['reemitted']}, "
                     f"unmetered {folds['unmetered']})" + ("  <-- UNMETERED: the turn's tokens are unknown" if folds["unmetered"] else ""))
        if n:
            keys = ("input_tokens", "cached_input_tokens", "cache_write_input_tokens", "output_tokens")
            lines.append("    metered last sum: " + " ".join(f"{k}={metered.get(k, 0)}" for k in keys))
            lines.append("    final thread total: " + " ".join(f"{k}={final_total.get(k)}" for k in keys))
        lines.append("    turn answer: " + ("; ".join(answers) if answers else "none recorded"))
        lines.append("    model rerouted: " + ("; ".join(reroutes) if reroutes else "none"))
        lines.append(f"    events_dropped: {ev.get('events_dropped')}; other events: "
                     + (", ".join(f"{k}={v}" for k, v in sorted(other.items())) or "none"))
    return "\n".join(lines)


# --- iterations ---------------------------------------------------------------

def iteration_of(path):
    path = bytes(path)
    count = int.from_bytes(path[:8], "little")
    coords = [int.from_bytes(path[8 + 4 * i:12 + 4 * i], "little") for i in range(count)]
    if len(coords) < 2:
        raise Refused(f"operation path {path.hex()} has no loop coordinate")
    return coords[-2]


def cmd_iterations(conn, text, stage="test"):
    raw, _, state = execution(conn, text)
    rows = []
    for occ, accepted, path in conn.execute(
            "select o.occurrence_id, o.accepted_attempt_id, o.operation_path from occurrences o "
            "where o.execution_id = ? and exists (select 1 from attempts a "
            "where a.occurrence_id = o.occurrence_id and a.stage_id = ?)", (raw, stage)):
        attempts = conn.execute("select count(*) from attempts where occurrence_id = ?", (occ,)).fetchone()[0]
        ordinal, status = None, "<no accepted TestReport>"
        if accepted is not None:
            ordinal = conn.execute("select attempt_ordinal from attempts where attempt_id = ?",
                                   (accepted,)).fetchone()[0]
            for (payload,) in conn.execute(
                    "select cast(payload_json as text) from transitions where attempt_id = ? "
                    "order by seq desc", (accepted,)):
                s = ((json.loads(payload).get("output") or {}).get("parsed") or {}).get("status")
                if s is not None:
                    status = s
                    break
        rows.append((iteration_of(path), attempts, ordinal, status))
    rows.sort()
    return f"execution {text} ({state})\n" + table(
        [[f"{stage}#iter-{i}", a, o, s] for i, a, o, s in rows],
        ["iteration", "attempts", "accepted_ordinal", "test_status"])


# --- params, variant, refined, refinecheck --------------------------------------

def invocation_params(conn, raw):
    row = conn.execute("select cast(invocation_json as text) from invocations where execution_id = ?",
                       (raw,)).fetchone()
    if row is None:
        raise Refused("no invocation row for this execution")
    return {p["name"]: p["value"] for p in jtext(row[0]).get("params") or []}


def cmd_params(conn, text):
    raw, _, state = execution(conn, text)
    rows = []
    for name, value in sorted(invocation_params(conn, raw).items()):
        v = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
        rows.append([name, len(v.encode()), hashlib.sha256(v.encode()).hexdigest()])
    return f"execution {text} ({state})\n" + table(rows, ["param", "bytes", "sha256"])


def variant_of(task, texts):
    """The variant whose kit text equals TASK, trailing newlines aside; else `unknown`."""
    if not isinstance(task, str):
        return "unknown"
    for name, body in texts:
        if task.rstrip("\n") == body.rstrip("\n"):
            return name
    return "unknown"


def kit_variants():
    return [(name, "".join(open(os.path.join(KIT, f)).read() for f in files)) for name, files in VARIANTS]


def cmd_variant(conn, text):
    raw, _, _ = execution(conn, text)
    return f'variant = "{variant_of(invocation_params(conn, raw).get("task"), kit_variants())}"'


def test_iterations(conn, raw, stage="test"):
    """[(iteration, status, feedback)] of the loop gate's accepted attempts, in order."""
    out = []
    for occ, accepted, path in conn.execute(
            "select o.occurrence_id, o.accepted_attempt_id, o.operation_path from occurrences o "
            "where o.execution_id = ? and exists (select 1 from attempts a "
            "where a.occurrence_id = o.occurrence_id and a.stage_id = ?)", (raw, stage)):
        status, feedback = "<no accepted TestReport>", ""
        if accepted is not None:
            for (payload,) in conn.execute("select cast(payload_json as text) from transitions "
                                           "where attempt_id = ? order by seq desc", (accepted,)):
                parsed = (json.loads(payload).get("output") or {}).get("parsed") or {}
                if parsed.get("status") is not None:
                    status, feedback = parsed["status"], parsed.get("feedback") or ""
                    break
        out.append((iteration_of(path), status, feedback))
    return sorted(out)


def refined_of(statuses):
    """yes when iteration 0 failed and a later iteration ran: the loop refined at least once."""
    return "yes" if len(statuses) >= 2 and statuses[0] == "failed" else "no"


def cmd_refined(conn, text):
    raw, _, _ = execution(conn, text)
    st = [s for _, s, _ in test_iterations(conn, raw)]
    return (f'refined = "{refined_of(st)}"\niterations = {len(st)}\n'
            f'final_test = "{st[-1] if st else "none"}"')


def agent_prompts(conn, raw):
    """[(stage, iteration-or-None, prompt text)] of every agent attempt, read from the artifact store."""
    out = []
    for attempt_id, stage, ordinal, _, _, proc, occurrence in agent_attempts(conn, raw):
        pid = proc.get("prompt")
        if not pid:
            continue
        row = conn.execute("select o.storage, cast(o.blob as text) from artifacts a "
                           "join cas.cas_objects o on o.object_id = a.object_id "
                           "where a.artifact_id = unhex(?)", (pid,)).fetchone()
        if row is None or row[0] != "inline":
            raise Refused(f"prompt artifact {pid} of {stage}#{ordinal} is not an inline CAS blob")
        path = conn.execute("select operation_path from occurrences where occurrence_id = ?",
                            (occurrence,)).fetchone()[0]
        try:
            it = iteration_of(path)
        except Refused:
            it = None
        out.append((stage, it, row[1]))
    return out


GATE_SUMMARY = re.compile(r"linekit-gate: (\d+) passed, (\d+) failed, (\d+) checks")
SUITE_SUMMARY = re.compile(r"linekit tests: (\d+) passed, (\d+) failed")
GATE_CAPSULE_PATH = "linekit-gate.sh"
LEAK_LINE_MIN = 30
# A check the gate declares: a functional case call or a house convention call.
GATE_CHECK_CALL = re.compile(r"^(?:(?:t|te) (G\d+-[\w-]+)|conv (C\d+-[\w-]+)) ", re.M)


def gate_checks(gate):
    """The number of distinct checks the gate's source declares (25 for gate/align-gate.sh)."""
    return len({g or c for g, c in GATE_CHECK_CALL.findall(gate)})


def gate_all_pass(gate):
    """The exact summary line the gate prints when every one of its checks passes."""
    n = gate_checks(gate)
    return f"linekit-gate: {n} passed, 0 failed, {n} checks"


def last_match(pattern, text):
    # The gate prints its summary LAST; a candidate's own output (check.sh runs
    # first) may print a look-alike earlier in the same tail.
    found = list(pattern.finditer(text))
    return found[-1] if found else None


def sanitised(text):
    # change.star's feedback rule (`tr -c '\040-\176' ' '`, then `\` and `"` to
    # spaces), then every whitespace run to one space.
    return " ".join(re.sub(r'[^\x20-\x7e]|[\\"]', " ", text).split())


def gate_forms(gate):
    lines = {sanitised(l) for l in gate.splitlines()}
    funcs = re.findall(r"^([A-Za-z_][A-Za-z0-9_]*)\(\) \{", gate, re.M)
    return sorted(l for l in lines if len(l) >= LEAK_LINE_MIN), funcs


def gate_leaks(gate, text, tree=False):
    s = sanitised(text)
    lines, funcs = gate_forms(gate)
    hits = []
    if GATE_MARKER in s:
        hits.append("marker")
    calls = sorted({g or c for g, c in re.findall(r"(?<![\w-])(?:(?:t|te) (G\d+-[\w-]+)|conv (C\d+-[\w-]+))", s)})
    if calls:
        hits.append(f"{len(calls)} case call(s) ({', '.join(calls[:4])}{', ...' if len(calls) > 4 else ''})")
    defs = [f for f in funcs if re.search(rf"(?<![\w-]){f}\(\) ?\{{", s)]
    if defs:
        hits.append("function definition(s) " + ", ".join(defs))
    whole = [l for l in lines if l in s]
    if whole:
        hits.append(f"{len(whole)} whole source line(s) (first: {whole[0][:60]!r})")
    if tree and GATE_CAPSULE_PATH in text:
        hits.append(f"names the gate's capsule path ({GATE_CAPSULE_PATH})")
    return hits


def cmd_leakscan(args):
    tree = bool(args) and args[0] == "--tree"
    files = args[1:] if tree else args
    gate = open(os.path.join(KIT, "gate", "align-gate.sh")).read()
    leaky = 0
    texts = []
    for f in files:
        if f.endswith(".tar"):
            # A `git archive` of a tree: every file member and every link, nothing followed.
            # git stores a symlink as a blob holding its target, so that target is its text.
            with tarfile.open(f) as tf:
                for m in tf.getmembers():
                    if m.issym():
                        texts.append((f"{f}:{m.name}", m.linkname.encode(), m.name))
                    elif m.isfile() or m.islnk():
                        texts.append((f"{f}:{m.name}", tf.extractfile(m).read(), m.name))
        else:
            with open(f, "rb") as fh:
                texts.append((f, fh.read(), None))
    for name, data, member in texts:
        hits = gate_leaks(gate, data.decode("utf-8", "replace"), tree)
        if tree and member is not None and GATE_CAPSULE_PATH in member:
            hits.append(f"its path names the gate's capsule path ({GATE_CAPSULE_PATH})")
        if hits:
            leaky += 1
            print(f"leak {name}: " + "; ".join(hits))
    print(f"leakscan: {len(texts)} text(s) scanned, {leaky} with a leak")
    return 1 if leaky else 0


def refine_cause(feedback):
    g = last_match(GATE_SUMMARY, feedback)
    t = last_match(SUITE_SUMMARY, feedback)
    parts = []
    if t is None or int(t.group(2)) > 0:
        parts.append("suite" if t else "suite(no summary in the tail)")
    if g is None or int(g.group(2)) > 0:
        parts.append("gate" if g else "gate(no summary in the tail)")
    return "+".join(parts) or "none"


GATE_FAIL = re.compile(r"FAIL ([CG]\d+-[A-Za-z0-9-]+):")
GATE_NAMED = re.compile(r"FAIL \(not shown in full\):((?: G\d+-[A-Za-z0-9-]+)+)")


def gate_fails(feedback):
    """The gate checks a feedback tail names as failed, in the gate's own block only: after the
    repository suite's last summary and up to the gate's last one (C<n>: house conventions)."""
    g = last_match(GATE_SUMMARY, feedback)
    t = last_match(SUITE_SUMMARY, feedback)
    block = feedback[(t.end() if t else 0):(g.start() if g else len(feedback))]
    names = GATE_FAIL.findall(block)
    for m in GATE_NAMED.finditer(block):
        names += m.group(1).split()
    return " ".join(names) or "none"


def final_gate(statuses, feedback, gate):
    """(ok, detail) for `final-gate`: the last iteration passed and the LAST gate summary in its
    feedback is exactly `gate_all_pass(gate)`. It refuses any other last summary, a forged
    all-pass of a smaller gate (`1 passed, 0 failed, 1 checks`) included, a failed last
    iteration, and a feedback with no gate summary. It does not refuse a candidate that prints
    the exact 25-check line itself (e.g. by overwriting the test capsule's writable
    /tmp/linekit-gate.sh): `clone-gate` (the kit's gate run outside kata) answers that, and
    `gate-unnamed` when the tip's tree names the capsule path literally (a file's text, a
    symlink's target or a member's path; a path assembled at run time passes it)."""
    want = gate_all_pass(gate)
    final = last_match(GATE_SUMMARY, feedback) if feedback is not None else None
    ok = bool(statuses) and statuses[-1] == "passed" and final is not None and final.group(0) == want
    return ok, (f"last iteration {statuses[-1] if statuses else 'none'}; gate summary "
                f"{final.group(0) if final else 'absent'} (want {want})")


def cmd_refinecheck(conn, text, test_command):
    raw, _, _ = execution(conn, text)
    params = invocation_params(conn, raw)
    lines, fails = [], 0

    def check(label, ok, detail=""):
        nonlocal fails
        lines.append(("PASS " if ok else "FAIL ") + label + ("" if ok or not detail else ": " + detail))
        fails += 0 if ok else 1

    v = variant_of(params.get("task"), kit_variants())
    check("variant", v == "refine-cell", f"variant {v}")
    gate = open(os.path.join(KIT, "gate", "align-gate.sh")).read()
    got_gate = params.get("gate_suite")
    check("gate-bound", isinstance(got_gate, str) and got_gate.rstrip("\n") == gate.rstrip("\n")
          and params.get("test_command") == test_command,
          f"gate_suite {'sha256 ' + hashlib.sha256(got_gate.encode()).hexdigest() if isinstance(got_gate, str) else 'absent'} vs kit "
          f"{hashlib.sha256(gate.encode()).hexdigest()}; test_command {params.get('test_command')!r}")
    prompts = agent_prompts(conn, raw)
    leaked = [(f"{s}#iter-{i}", h) for s, i, p in prompts if (h := gate_leaks(gate, p))]
    check("gate-unseen", prompts and not leaked,
          f"{len(prompts)} prompt(s) read; the gate's source is in: "
          + (" | ".join(f"{w} ({'; '.join(h)})" for w, h in leaked) or "none"))
    its = test_iterations(conn, raw)
    st = [s for _, s, _ in its]
    check("refined", refined_of(st) == "yes", "iterations " + " ".join(f"{i}:{s}" for i, s, _ in its))
    check("final-gate", *final_gate(st, its[-1][2] if its else None, gate))
    cause = refine_cause(its[0][2]) if its and st[0] == "failed" else "none (iteration 0 did not fail)"
    lines.append(f"INFO refine_cause = {cause} (iteration 0's feedback)")
    if its and st[0] == "failed":
        lines.append(f"INFO iter0_gate_fails = {gate_fails(its[0][2])}")
    lines.append(f"refinecheck: {fails} failed")
    return "\n".join(lines), fails


# --- self-test ----------------------------------------------------------------

def self_test():
    ok = True

    def check(label, got, want):
        nonlocal ok
        if got != want:
            ok = False
            print(f"FAIL {label}: got {got!r}, want {want!r}")

    u = "01M688FTGPRW37VSV2F0BB3NX0"
    check("ulid round trip", ulid_text(ulid_bytes(u)), u)
    path = (3).to_bytes(8, "little") + b"".join(x.to_bytes(4, "little") for x in (7, 2, 1))
    check("iteration = second-to-last coordinate", iteration_of(path), 2)
    measured_sub = {"input": 10, "output": 2, "cache_read": 5, "cache_write": 0,
                    "cost": {"quality": "unavailable", "backend": "codex", "model": "m"}}
    unmetered_codex = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0,
                       "cost": {"quality": "unavailable", "backend": "codex_app_server", "model": "m"}}
    nanocode_measured = dict(measured_sub, cost={"quality": "unavailable", "backend": "nanocode_openai", "model": "m"})
    nanocode_unmetered = dict(unmetered_codex, cost={"quality": "unavailable", "backend": "nanocode_openai", "model": "m"})
    check("codex subscription turn is measured", cost_text(measured_sub, "codex_app_server"), "unavailable(codex)")
    check("codex unmetered turn is unknown", cost_text(unmetered_codex, "codex_app_server"), "unknown")
    check("nanocode measured turn keeps its tokens", unmeasured(nanocode_measured, "nanocode_openai"), False)
    check("nanocode unmetered turn is unknown", cost_text(nanocode_unmetered, "nanocode_openai"), "unknown")
    ambiguous = dict(unmetered_codex, cost={"quality": "unavailable", "backend": "", "model": ""})
    check("an unknown answer's empty-backend charge is unknown", cost_text(ambiguous, "codex_app_server"), "unknown")
    est = {"input": 1, "output": 1, "cache_read": 0, "cache_write": 0,
           "cost": {"quality": "estimated", "micro_usd": 1500, "basis": {}}}
    check("estimated cost", cost_text(est, "codex_app_server"), "estimated:0.001500USD")
    folds, metered, final, answers, reroutes, other = summarize_evidence({"events": [
        {"event": "token_usage_frame", "fold": "metered", "total": {"input_tokens": 5}, "last": {"input_tokens": 5}},
        {"event": "token_usage_frame", "fold": "reemitted", "total": {"input_tokens": 5}, "last": {"input_tokens": 5}},
        {"event": "token_usage_frame", "fold": "metered", "total": {"input_tokens": 12}, "last": {"input_tokens": 7}},
        {"event": "turn_answer", "source": "summary", "phase": "final_answer", "items_view": "summary"},
        {"event": "model_rerouted", "from_model": "a", "to_model": "b", "this_turn": True},
        {"event": "refused_callback", "method": "x", "id": "1"}], "events_dropped": 0})
    check("folds", folds, {"metered": 2, "reemitted": 1, "unmetered": 0})
    check("metered last sum equals final total", (metered["input_tokens"], final["input_tokens"]), (12, 12))
    check("answer", answers, ["source=summary phase=final_answer items_view=summary"])
    check("reroute", reroutes, ["a->b this_turn=True"])
    check("other", other, {"refused_callback": 1})
    totals = {"find": {"unknown": 0, "input": 500, "output": 40, "cache_read": 0, "cache_write": 0},
              "verify": {"unknown": 1, "input": 10, "output": 5, "cache_read": 3, "cache_write": 0}}
    check("record: known part summed, unknown charges counted apart", record_fields(totals),
          ({"input": 510, "output": 45, "cache_read": 3, "cache_write": 0}, 1))
    # record's cost: the priced set mirrors evidence-page.py PRICED at e2942e163, each priced harness
    # runs an adapter no other harness runs, and only an all-Estimated run on those adapters is summed.
    check("PRICED mirrors evidence-page.py at e2942e163", PRICED, ("codex-stock", "nanocode-anthropic"))
    priced = priced_adapters()
    check("priced adapters", priced, {"codex_app_server": "codex-stock", "nanocode_anthropic": "nanocode-anthropic"})
    hc0 = harness_config()
    check("no unpriced harness runs a priced adapter",
          [h for h in hc0.HARNESSES if h not in PRICED
           and set(re.findall(r'^adapter = "([^"]*)"$', hc0.agent_block(h, "<ca>"), re.M)) & set(priced)], [])
    e = lambda m: {"input": 1, "output": 1, "cache_read": 0, "cache_write": 0,
                   "cost": {"quality": "estimated", "micro_usd": m, "basis": {}}}
    na, cx = "nanocode_anthropic", "codex_app_server"
    # StageUsage::unbilled() as kata serializes it (34d5c77c8, crates/types/src/metering.rs).
    unbilled = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0, "cache_savings_micro_usd": 0,
                "cost": {"quality": "authoritative", "micro_usd": 0}, "cost_micro_usd": 0}
    for label, charges, want in (
            ("nanocode-anthropic, failed attempt's charge included", [(na, e(1000)), (na, e(2500))], ("estimated", 3500)),
            ("codex-stock under api_key", [(cx, e(10499)), (cx, e(10499))], ("estimated", 20998)),
            ("codex subscription turn", [(cx, measured_sub)], ("unavailable", None)),
            ("an estimated charge beside a subscription one", [(cx, e(5)), (cx, measured_sub)], ("unavailable", None)),
            ("nanocode-openai", [("nanocode_openai", nanocode_measured)], ("unavailable", None)),
            ("claude-agent-acp", [("generic_acp", dict(measured_sub, cost={"quality": "unavailable",
                                                                          "backend": "generic_acp", "model": "m"}))],
             ("unavailable", None)),
            ("a priced run with an unmeasured charge", [(na, e(2500)), (cx, unmetered_codex)], ("unavailable", None)),
            ("a priced run with an unrecorded charge", [(na, None), (na, e(2500))], ("unavailable", None)),
            ("a priced adapter beside an unpriced one", [(na, e(2500)), ("generic_acp", measured_sub)],
             ("unavailable", None)),
            ("a refused attempt's authoritative 0 beside an estimate", [(na, unbilled), (na, e(1500))],
             ("estimated", 1500)),
            ("a transient attempt's authoritative 0 beside a subscription turn",
             [("nanocode_openai", unbilled), ("nanocode_openai", nanocode_measured)], ("unavailable", None)),
            ("only charges that billed nothing", [(na, unbilled), (na, unbilled)], ("unavailable", None)),
            ("no charge", [], ("unavailable", None))):
        check(f"cost_fields: {label}", cost_fields(charges, priced)[:2], want)

    def cost_refused(charges):
        try:
            cost_fields(charges, priced)
        except Refused:
            return True
        return False
    check("cost_fields refuses an estimate PRICED does not admit, an authoritative cost but kata's 0, "
          "a malformed estimate",
          [cost_refused(c) for c in ([("generic_acp", e(1))], [("nanocode_openai", e(1))], [(None, e(1))],
                                     [(na, dict(e(1), cost={"quality": "authoritative", "micro_usd": 1}))],
                                     [(na, dict(unbilled, cost={"quality": "authoritative", "micro_usd": 1}))],
                                     [(na, dict(e(1), cost={"quality": "authoritative", "micro_usd": 0}))],
                                     [(na, dict(unbilled, cost={"quality": "authoritative", "micro_usd": False}))],
                                     [(na, dict(unbilled, cost={"quality": "authoritative"}))],
                                     [(na, dict(e(1), cost={"quality": "estimated", "basis": {}}))],
                                     [(na, dict(e(1), cost={"quality": "estimated", "micro_usd": True}))],
                                     [(na, dict(e(1), cost={}))])],
          [True] * 11)
    check("kata's authoritative 0 is a known zero, printed as such",
          (billed_nothing(unbilled), unmeasured(unbilled, na), cost_text(unbilled, na)),
          (True, False, "authoritative:0.000000USD"))
    # turncheck model-reported: harness-config.py holds exactly one accepted alias, and it is accepted
    # only for claude-agent-acp's generic_acp attempt that declared claude-sonnet-5-5.
    harnesses, answers, pinned = harness_table()
    check("picker answers: exactly claude-agent-acp's measured `sonnet`",
          {h: {k: v[0] for k, v in t.items()} for h, t in answers.items()},
          {"claude-agent-acp": {("generic_acp", "claude-sonnet-5-5"): "sonnet"}})
    s55 = "claude-sonnet-5-5"
    for label, args, want in (
            ("the exact pin, every harness", [(h, "x", s55, s55) for h in harnesses], True),
            ("claude-agent-acp's picker answer", [("claude-agent-acp", "generic_acp", s55, "sonnet")], True),
            ("the alias on every other harness", [(h, "generic_acp", s55, "sonnet") for h in harnesses
                                                  if h != "claude-agent-acp"], False),
            ("the alias under another adapter", [("claude-agent-acp", "nanocode_anthropic", s55, "sonnet")], False),
            ("the alias without the declared pin", [("claude-agent-acp", "generic_acp", "-", "sonnet")], False),
            ("another picker value", [("claude-agent-acp", "generic_acp", s55, v) for v in ("haiku", "opus", "default",
                                                                                           "Sonnet", "-")], False)):
        check(f"model_reported_ok: {label}", {model_reported_ok(h, a, d, r, s55, answers)[0] for h, a, d, r in args},
              {want})
    check("model_reported_ok: the alias against another pin",
          model_reported_ok("claude-agent-acp", "generic_acp", "gpt-6-luna", "sonnet", "gpt-6-luna", answers)[0], False)
    # How turncheck combines the attempts: a completed attempt is needed, and EVERY one must pass,
    # wherever in the list the one that fails sits.
    acp, exact, alias, bad = ("claude-agent-acp", ("generic_acp", s55, s55), ("generic_acp", s55, "sonnet"),
                              ("generic_acp", s55, "haiku"))
    for label, harness, attempts, want in (
            ("no completed attempt", acp, [], False),
            ("one exact attempt", "nanocode-anthropic", [("nanocode_anthropic", s55, s55)], True),
            ("an exact attempt beside the alias", acp, [exact, alias], True),
            ("every attempt the alias", acp, [alias, alias], True),
            ("a refused attempt after an accepted one", acp, [alias, bad], False),
            ("a refused attempt before an accepted one", acp, [bad, alias], False),
            ("a refused attempt between accepted ones", acp, [exact, bad, alias], False),
            ("the alias beside an exact attempt on another harness", "nanocode-anthropic", [exact, alias], False)):
        check(f"model_reported_check: {label}", model_reported_check(harness, attempts, s55, answers)[0], want)
    check("model_reported_check: the PASS note names the accepted answer",
          model_reported_check(acp, [exact, alias], s55, answers)[2],
          [f"sonnet is {answers[acp][('generic_acp', s55)][1]}"])
    # turncheck judges MODEL only as HARNESS's pin, and harness-config.py's agent_block and
    # prelude.sh's MODEL state the same pin per harness.
    check("pinned models", pinned, {"codex-stock": "gpt-6-luna", "nanocode-openai": "gpt-6-luna",
                                    "claude-agent-acp": s55, "nanocode-anthropic": s55})
    hc = harness_config()
    check("agent_block declares each harness's pinned model",
          {h: re.findall(r'^model = "([^"]*)"$', hc.agent_block(h, "<ca>"), re.M) for h in harnesses},
          {h: [pinned[h]] for h in harnesses})
    prelude = {h: m for hs, m in re.findall(r"^([a-z| -]+)\) MODEL=(\S+) ;;$",
                                           open(os.path.join(KIT, "prelude.sh")).read(), re.M)
               for h in (x.strip() for x in hs.split("|"))}
    check("prelude.sh sets MODEL to each harness's pinned model", prelude, pinned)

    def turncheck_refuses(model, harness):
        try:
            cmd_turncheck(None, u, model, harness)  # a valid id: only the MODEL/HARNESS refusals can refuse
        except Refused:
            return True
        except Exception:
            return False
        return False
    check("turncheck refuses a MODEL that is not HARNESS's pin, and an unknown HARNESS",
          [turncheck_refuses(m, h) for m, h in (("sonnet", "nanocode-anthropic"), ("sonnet", "claude-agent-acp"),
                                                 ("gpt-6-luna", "claude-agent-acp"), (s55, "codex-stock"),
                                                 ("gpt-6-luna", "nanocode-anthropic"), (s55, "claude"))],
          [True] * 6)
    check("turncheck admits each harness's pin past its refusals (it reaches the ledger)",
          [turncheck_refuses(pinned[h], h) for h in harnesses], [False] * len(harnesses))
    texts = [("task-only", "T\n"), ("refine-addendum", "T\nA\n"), ("refine-cell", "T\nR\n")]
    check("variant: $(cat) strips the final newline", variant_of("T\nA", texts), "refine-addendum")
    check("variant: exact JSON bytes", variant_of("T\nR\n", texts), "refine-cell")
    check("variant: other text is unknown", variant_of("T\nX", texts), "unknown")
    check("variant: kit texts are distinct", len({b.rstrip() for _, b in kit_variants()}), 3)
    check("refined: fail then pass", refined_of(["failed", "passed"]), "yes")
    check("refined: fail, fail (exhausted) still refined", refined_of(["failed", "failed"]), "yes")
    check("refined: first pass", refined_of(["passed"]), "no")
    check("refined: one failed iteration only", refined_of(["failed"]), "no")
    check("refine_cause: gate only", refine_cause("linekit tests: 9 passed, 0 failed, 8 suites "
                                                  "linekit-gate: 20 passed, 2 failed, 22 checks"), "gate")
    check("refine_cause: both", refine_cause("linekit tests: 9 passed, 1 failed, 8 suites "
                                             "linekit-gate: 0 passed, 22 failed, 22 checks"), "suite+gate")
    check("refine_cause: the gate's own (last) summary wins over a forged earlier one",
          refine_cause("linekit-gate: 22 passed, 0 failed, 22 checks linekit tests: 9 passed, 0 failed "
                       "linekit-gate: 21 passed, 1 failed, 22 checks"), "gate")
    gate = open(os.path.join(KIT, "gate", "align-gate.sh")).read()
    lines, funcs = gate_forms(gate)
    check("gate forms: lines and functions found", (len(lines) > 20, sorted(funcs)),
          (True, ["argv", "call", "conv", "cut40", "finish", "shown", "t", "te", "verdict"]))
    conv_fb = ("linekit tests: 100 passed, 0 failed, 8 suites FAIL C1-command-header: house convention: line 1 of "
               "every new lib/cmd_NAME.sh is exactly [# linekit-cmd: NAME]; fix: lib/cmd_align.sh line 1 "
               "[# linekit-cmd: align]; FAIL C2-manifest: house convention: the file MANIFEST at the top of the "
               "tree holds the line [provides: NAME] for every new command NAME; fix: add to MANIFEST the line(s) "
               "[provides: align] FAIL C3-suite-footer: house convention: the last line of every new "
               "tests/t_NAME.sh is exactly [# end of t_NAME]; fix: tests/t_align.sh last line [# end of t_align]; "
               "linekit-gate: 22 passed, 3 failed, 25 checks")
    check("leak: honest convention feedback is clean", gate_leaks(gate, conv_fb), [])
    check("leak: a convention tree (header, manifest, footer) is clean",
          gate_leaks(gate, "# linekit-cmd: align\nprovides: align\n# end of t_align\n", True), [])
    check("leak: a convention call", [h.split(" (")[0] for h in gate_leaks(gate, 'conv C2-manifest "the file')],
          ["1 case call(s)"])
    check("gate_fails: conventions only", gate_fails(conv_fb), "C1-command-header C2-manifest C3-suite-footer")
    check("gate_fails: the candidate's own forged FAIL before the suite summary is ignored",
          gate_fails("FAIL C9-forged: x linekit tests: 9 passed, 0 failed, 8 suites FAIL G1-dot-first: r "
                     "FAIL (not shown in full): G7-negative-zero G9-header-right-aligned FAIL C2-manifest: h "
                     "linekit-gate: 19 passed, 4 failed, 25 checks"),
          "G1-dot-first C2-manifest G7-negative-zero G9-header-right-aligned")
    honest = ("Iteration 1: the tests FAILED on your last attempt. The tail of their output: "
              "linekit tests: 100 passed, 0 failed, 8 suites FAIL G13-space-separator: -s ' ' cuts at EVERY "
              "single space: two spaces in a row make an empty cell   run:  linekit align -s ' ', stdin "
              "[a  b][c d e]   want: exit 0, stdout [a     b][c  d  e] linekit-gate: 21 passed, 1 failed, 22 checks "
              "The project's tests run with: sh tests/check.sh; c=$?; sh /tmp/linekit-gate.sh; g=$?")
    check("leak: honest feedback and the test_command are clean", gate_leaks(gate, honest), [])
    check("leak: the marker", gate_leaks(gate, "x " + GATE_MARKER + " y"), ["marker"])
    check("leak: a case call after sanitising", [h.split(" (")[0] for h in gate_leaks(gate, 't G7-negative-zero "$N')],
          ["1 case call(s)"])
    check("leak: a function definition", gate_leaks(gate, "verdict() { # NAME"), ["function definition(s) verdict"])
    one = next(l for l in gate.splitlines() if l.startswith("\tprintf '  run:"))
    check("leak: one whole source line, newlines and quotes sanitised",
          [h.split(" (")[0] for h in gate_leaks(gate, "zz\n" + one.replace('"', "\\") + "\nzz")],
          ["1 whole source line(s)"])
    check("leak: the capsule path counts in a tree only",
          (gate_leaks(gate, "cat /tmp/linekit-gate.sh"), len(gate_leaks(gate, "cat /tmp/linekit-gate.sh", True))),
          ([], 1))
    declared = re.search(r"^CHECKS=(\d+)$", gate, re.M)
    check("gate declares 25 checks (25 case calls, CHECKS=25)",
          (gate_checks(gate), declared and int(declared.group(1))), (25, 25))
    check("final-gate: the exact all-pass summary", gate_all_pass(gate), "linekit-gate: 25 passed, 0 failed, 25 checks")
    p25 = "linekit tests: 100 passed, 0 failed, 8 suites linekit-gate: 25 passed, 0 failed, 25 checks"
    check("final-gate: honest all-pass", final_gate(["failed", "passed"], p25, gate)[0], True)
    check("final-gate: a candidate's earlier look-alike does not matter",
          final_gate(["failed", "passed"], "linekit-gate: 1 passed, 0 failed, 1 checks " + p25, gate)[0], True)
    for label, fb in (("a forged one-check gate", "linekit tests: 100 passed, 0 failed, 8 suites "
                       "linekit-gate: 1 passed, 0 failed, 1 checks"),
                      ("a smaller all-pass", "linekit-gate: 24 passed, 0 failed, 24 checks"),
                      ("a wider total", "linekit-gate: 25 passed, 0 failed, 250 checks"),
                      ("a failure", "linekit-gate: 24 passed, 1 failed, 25 checks"),
                      ("an all-pass followed by a forged last summary", p25 + " linekit-gate: 1 passed, 0 failed, 1 checks"),
                      ("no summary", "linekit tests: 100 passed, 0 failed, 8 suites")):
        check(f"final-gate refuses {label}", final_gate(["failed", "passed"], fb, gate)[0], False)
    check("final-gate refuses a failed last iteration", final_gate(["failed", "failed"], p25, gate)[0], False)
    check("final-gate refuses no iteration", final_gate([], None, gate)[0], False)
    # --leakscan counts what it read; e2-oracles.sh's gate-unnamed grep agrees with that line.
    with tempfile.TemporaryDirectory() as td:
        tar = os.path.join(td, "tip.tar")
        with tarfile.open(tar, "w") as tf:
            for name, body in (("README.md", b"x\n"), ("lib/cmd_a.sh", b"# linekit-cmd: a\n"), ("tests/t_a.sh", b"y\n")):
                info = tarfile.TarInfo(name)
                info.size = len(body)
                tf.addfile(info, io.BytesIO(body))
            d = tarfile.TarInfo("lib")
            d.type = tarfile.DIRTYPE
            tf.addfile(d)
        plain = os.path.join(td, "fb.txt")
        with open(plain, "w") as fh:
            fh.write("linekit-gate: 25 passed, 0 failed, 25 checks\n")
        empty = os.path.join(td, "empty.tar")
        tarfile.open(empty, "w").close()
        out = {}
        for key, args in (("tree", ["--tree", tar]), ("both", [tar, plain]), ("empty", ["--tree", empty])):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cmd_leakscan(args)
            out[key] = (buf.getvalue().splitlines()[-1], rc)
    check("leakscan counts the members it read, not its arguments", out,
          {"tree": ("leakscan: 3 text(s) scanned, 0 with a leak", 0),
           "both": ("leakscan: 4 text(s) scanned, 0 with a leak", 0),
           "empty": ("leakscan: 0 text(s) scanned, 0 with a leak", 0)})
    # --tree names the capsule path through a symlink's target and through a member's path,
    # and a link to anything else is clean.
    with tempfile.TemporaryDirectory() as td:
        tar = os.path.join(td, "links.tar")
        with tarfile.open(tar, "w") as tf:
            for name, target in (("tests/helper", "/tmp/linekit-gate.sh"), ("tests/ok", "t_a.sh")):
                info = tarfile.TarInfo(name)
                info.type, info.linkname = tarfile.SYMTYPE, target
                tf.addfile(info)
            body = b"echo hi\n"
            info = tarfile.TarInfo("tests/linekit-gate.sh")
            info.size = len(body)
            tf.addfile(info, io.BytesIO(body))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cmd_leakscan(["--tree", tar])
    check("leakscan --tree: a symlink's target and a member's path name the capsule path", (buf.getvalue(), rc),
          (f"leak {tar}:tests/helper: names the gate's capsule path (linekit-gate.sh)\n"
           f"leak {tar}:tests/linekit-gate.sh: its path names the gate's capsule path (linekit-gate.sh)\n"
           "leakscan: 3 text(s) scanned, 2 with a leak\n", 1))
    oracles = open(os.path.join(KIT, "e2-oracles.sh")).read()
    pat = re.search(r"grep -q '(\^leakscan: [^']*)' \"\$EV/gate-unnamed.txt\"", oracles)
    accepts = (lambda line: subprocess.run(["grep", "-q", pat.group(1)], input=line + "\n", text=True).returncode == 0)
    check("e2-oracles.sh gate-unnamed: accepts a clean scan of N >= 1 members, refuses an empty one or a leak",
          pat and (accepts(out["tree"][0]), accepts("leakscan: 57 text(s) scanned, 0 with a leak"),
                   accepts(out["empty"][0]), accepts("leakscan: 3 text(s) scanned, 1 with a leak"),
                   accepts("leakscan: 1 file(s), 0 with a leak")),
          (True, True, False, False, False))
    print("ledger.py self-test: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def main(argv):
    if argv[1:] == ["--self-test"]:
        return self_test()
    if argv[1:2] == ["--leakscan"]:
        if not [a for a in argv[2:] if a != "--tree"]:
            sys.stderr.write(__doc__)
            return 2
        return cmd_leakscan(argv[2:])
    if len(argv) < 3:
        sys.stderr.write(__doc__)
        return 2
    data_dir, verb, args = argv[1], argv[2], argv[3:]
    verbs = {"execs": (cmd_execs, (0, 1)), "head": (cmd_head, (1, 1)), "stages": (cmd_stages, (1, 1)),
             "turns": (cmd_turns, (1, 1)), "iterations": (cmd_iterations, (1, 1)),
             "record": (cmd_record, (1, 1)), "turncheck": (cmd_turncheck, (3, 3)),
             "params": (cmd_params, (1, 1)), "variant": (cmd_variant, (1, 1)),
             "refined": (cmd_refined, (1, 1)), "refinecheck": (cmd_refinecheck, (2, 2))}
    if verb not in verbs or not verbs[verb][1][0] <= len(args) <= verbs[verb][1][1]:
        sys.stderr.write(__doc__)
        return 2
    try:
        conn = connect(data_dir)
        answer = verbs[verb][0](conn, *args)
        if verb in ("turncheck", "refinecheck"):
            print(answer[0])
            return 0 if answer[1] == 0 else 1
        print(answer)
    except Refused as e:
        sys.stderr.write(f"ledger.py: refused: {e}\n")
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
