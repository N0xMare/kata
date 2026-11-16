# Evidence

This page records the real-model runs that kata's pre-release claims rest on:

- **E1**: a typed review of a real pull request;
- **E2**: implement, test and fix a change, then deliver it as a pull request;
- **E3**: kill the main, the worker or the host at fixed points, and check the settlement;
- **E9**: a clean machine, from clone to a first E1 run.

Three rounds produced the records: the counted parity round (E1 and E2), the
0.0.1 round (E3 and E9), and a rerun round (E3's `P1-host` and `P2-host`); each
record names the build it ran on. The 0.0.1 round's
spend, which the round's own tally (`spend-tally.py`, uncommitted, over the 21
executions' databases: its records, plus one precondition turn on each Anthropic
model and `just live-nanocode`'s two `nanocode_anthropic` cells, which leave no
record) read and no committed record re-derives, was $0.211328 known at
Anthropic's list price, plus six Anthropic attempts kata could not meter, which
its stop rule counted at $0.25 each: $1.711328. The OpenAI arm ran on the ChatGPT
subscription, with no per-token charge, and Anthropic's own per-run figure is not
attributable. The rerun round's spend, read the same way over its 4 executions (its
two records and `just live-nanocode`'s two `nanocode_anthropic` cells), was $0.053842
known at list price, plus two attempts kata could not meter (`P1-host` and
`P2-host`), at $0.25 each: $0.553842.

Every result below is rendered from a committed run record under
`docs/evidence/runs/`. A case with no record reads **not yet run**. Nothing on this
page claims more than its records. `just evidence-check` refuses a page whose
rendered sections differ from the records, and a record that is incomplete or
inconsistent (`scripts/evidence-page.py` states the refused set).

## Rules for every run

- **Build.** E1, E2 and E9: a release build (`cargo build --release --locked`)
  from a clean checkout of the commit under test. E3's cells are kata's own test
  rig, so they run the debug binaries the workspace test build makes from a clean
  checkout of that commit (`just e3-crash-matrix`; the rig spawns
  `CARGO_BIN_EXE_kata` and the `kata-worker` beside it,
  `bin/kata/tests/agent_change_rig/mod.rs`), not a release build; an E3 record's
  `tree.txt` names that tree and whether it was clean.
- **Provenance.** The record names the commit under test (`kata_sha`) and its
  tree (`kata_tree`, `git rev-parse <kata_sha>^{tree}`). A nanocode run
  (`nanocode-openai`, `nanocode-anthropic`) names the nanocode revision kata
  pins at that commit (`nanocode_rev`). A baseline run names the vendor that
  answered (`vendor_version`): the line its `--version` printed inside the
  bound node environment, `codex-cli <version>` from `codex --version` on
  `codex-stock`, the bare `<version>` from `claude-agent-acp --version` on
  `claude-agent-acp`. The vendor binary comes from the node's environment,
  not from `kata_sha`. In kata's private archive, which keeps
  the full history, the check refuses a `kata_sha` that is not an ancestor of
  HEAD and a `kata_tree` that is not its tree. The public repository is one
  squashed commit of a later archive revision, and neither id resolves there:
  the squash commit is not `kata_sha`, and its tree is not `kata_tree`,
  because that revision also holds the run records (and whatever landed after
  the run). There the check reads only their shape. Both ids are checkable
  only against the archive, or `kata_tree` against a checkout of the tested
  source, which has that tree id (`git rev-parse HEAD^{tree}`) whichever
  commit carries it.
- **Oracles.** Every outcome is read from something kata does not own: git,
  the forge's CLI (`gh`), the remote, the filesystem, a second read-only
  handle on the database (`sqlite3 -readonly`), a client-side transcript of
  the event stream, or the provider. The record's `outcome_source` names the
  artifact that holds that read. kata's own report of a run is never its
  oracle.
- **Harnesses.** E1 and E2 ran on two parity pairs, each a stock vendor
  harness (the baseline) beside kata's embedded nanocode harness for the same
  provider, both on the pair's one model and reasoning effort. The baselines
  ran once, in the counted round: kata no longer carries
  their adapters, and the check refuses a baseline record at any other
  `kata_sha`:

  | Pair | Baseline | nanocode | Model / effort |
  |---|---|---|---|
  | OpenAI | `codex-stock` (the stock codex app server) | `nanocode-openai` | `gpt-6-luna` / `medium` |
  | Anthropic | `claude-agent-acp` (generic ACP on claude-agent-acp) | `nanocode-anthropic` | `claude-sonnet-5-5` / `medium` |

  The check refuses a record whose harness is in neither pair, or whose
  `model` or `effort` is not its pair's (`PAIRS` in
  `scripts/evidence-page.py`). E3 and E9 run on the two nanocode harnesses
  (`nanocode-openai`, and `nanocode-anthropic` as the anthropic arm); the check
  refuses either cell on any other harness.
- **Capsule network.** A nanocode capsule is `offline`: its model traffic
  leaves from the worker, never the capsule. A baseline's capsule
  (`codex-stock`, `claude-agent-acp`) is `vendor-egress-only`. Each record
  states which, and the check refuses a record whose statement does not
  match its harness.
- **Spend.** kata prices a turn only on `nanocode-anthropic` under an API key
  (`AdapterKind::billing_backend`; the check's `PRICED` is held equal to it),
  from Anthropic's Claude 5 list prices. The builds that ran the baselines — the
  vendor adapters are gone from the current build, and their records stay as
  measured — also priced `codex-stock`, from the OpenAI price table (the check's
  `HISTORICAL_PRICED`). On every
  other harness under either login, and on a priced harness under a
  subscription login (`credential_mode = "subscription"`), kata records the
  tokens of each completed model call whose usage the adapter reports, and a
  cost of `unavailable`: it prices no
  `nanocode-openai` or `claude-agent-acp` turn, never prices a
  subscription call, and never records an unmeasured call as zero. On
  `codex-stock` a call is one sampling response: kata sums each response's
  `last` once, on the usage frame whose thread `total` advanced by exactly
  it. A turn with a frame whose `total` moved any other way is unmetered,
  never a partial count: its cost is `unavailable`, and the stage row's
  token counts read `0`, which there means unmeasured, not zero. Each frame's `total`, `last`
  and fold is in the turn's session evidence, so a reader can compare the
  recorded tokens with the vendor's own thread total.
- **Provider side.** `tokens_provider` and `cost_provider` state what the
  provider itself reported for the run, never kata's copy of a vendor frame:
  the four counts and the dollar figure (`$<amount>`), or `unavailable:` with
  the reason. A subscription login has no per-token view (`unavailable: a
  subscription login has no per-token view`). Under an API key, where the
  provider's usage cannot be attributed to one run, the ruled value is
  `unavailable: per-run provider usage not attributable`; a record states
  figures only when they were read for that run alone. The check reads only
  the shape: it refuses a `tokens_provider` or `cost_provider` that is
  neither the figures nor `unavailable:` with a non-blank reason, and does
  not check which reason, or whether a figure was attributable.
- **Unknown usage.** Every record, of every cell, states kata's KNOWN tokens
  in `tokens_recorded` (every charge kata measured, failed attempts' terminal
  charges included) and counts the usage kata does not know beside it, never
  folded into the total as 0; a run whose oracles pass with some is still a
  `pass`. There are two units. An unknown CHARGE is one attempt kata could
  not meter (an unmetered codex turn, an unmeasured charge, a terminal
  attempt that carries no charge, a killed attempt), however many model calls
  it issued; `ledger.py record` counts these. An unmetered CALL is one model
  call issued whose usage is unknown. On E1, E2 and E9 records
  `unmetered_calls` is ledger.py's count, so its unit is the charge, and the
  row shows `(+n unknown charge(s))`. An E3 record states both:
  `unmetered_calls`, the rig's issued calls of unknown usage (every call of
  a killed attempt), and `unknown_charges`, ledger.py's charges, which
  `e3-finish.py` adds; its row shows `(+n call(s), usage unknown, in m
  unknown charge(s))`. One killed attempt is one charge whatever it issued
  (4 calls, 1 charge is valid), and `P1`'s killed attempt is never sent (1
  charge, 0 calls). So on `P1` and `P1-host` the check refuses any issued
  call (`unmetered_calls` is exactly 0, beside any number of charges), and
  in every other case it refuses issued calls with no unknown charge, and
  fewer issued calls than charges.
  On a void E3 record no reader counted the calls: `unmetered_calls` is a
  lower bound (one per unknown charge; 0 on `P1` and `P1-host`), and the row
  says `at least`. `tokens_recorded = "unknown"` is only for a fail or a void
  run of which kata knows no charge; the check refuses it on a pass.
- **Sanitization.** Every artifact passes `just evidence-check` before it is
  committed. It refuses credentials, auth headers, bearer and OAuth tokens,
  cookie values, private session data (a host's public IP address among
  them), email addresses and unsanitized provider payloads, by pattern (`scripts/evidence-sanitize.py` states every
  rule), including inside JSON escaped in a JSONL transcript's strings.
  `just evidence-sanitize <files>` redacts those values in a raw
  transcript, in place, to `[redacted-<class>-<n>]` markers, and keeps
  escaped JSON valid. Read every artifact before committing it: a pattern
  check cannot see a secret in a shape it does not name.

## The evidence kit

The programs that read every committed outcome from outside kata are in
[`scripts/evidence-kit/`](../../scripts/evidence-kit/), byte for byte as the
runs used them: `e1-run.sh` (one E1 run and its eight oracles),
`e2-oracles.sh` (an E2 run's oracles), `ledger.py` (every read of kata's
database, through a second read-only SQLite handle: the frozen head, the
stages, the turns and the spend lines) and `score-e1.py` (an E1 review's
validation and seeded score). The 0.0.1 round's E3 and E9 readers are in
[`scripts/evidence-kit/round-0.0.1/`](../../scripts/evidence-kit/round-0.0.1/):
`e3-finish.py` (an E3 record's spend, finished from the run's database through
`ledger.py`), `e9-verdict.py` (the E9 verdict) and `spend-tally.py` (the round's
spend over every kept database, and its stop rule). No manifest pins those
three (an E3 or E9 record lists no `kit-sha256.txt`, and the check compares only
the files directly under `scripts/evidence-kit/`); the round compares its kit's
copies with these bytes before it starts. A non-void E2 `pr` or `refine` record lists
`kit-sha256.txt`, the manifest of the kit snapshot its run judged from, and
`just evidence-check` refuses one that lists none, and a record whose
manifest does not pin each of those files at its committed bytes; an E1 run writes no manifest, so nothing ties an E1 record
to those bytes. The rest of the kit is not committed. Its held-out part
stays private because E2 keeps it from every candidate: the wrap and align
oracles and the refine cell's gate (`oracle-e2.sh`, `oracle-align.sh`,
`gate/`), and the refine cell's params file. `e1-run.sh` and
`e2-oracles.sh` call other kit files by name (the seeded defect lists, the
held-out oracles), and `ledger.py`'s `record`, `turncheck`, `variant` and
`refinecheck` load the kit's `harness-config.py`, task texts or gate, so
those do not run from this directory alone: they are committed so that the
code that judged each record can be read, and checked against its manifest. Each script's header
states its arguments. A kit change cannot land while a committed record's
manifest pins the older bytes: the check refuses it.

## Run records

One directory per run, `runs/<run-id>/`, holding `run.toml` and the
sanitized artifacts it lists. The run id is
`<cell>-<case>-<harness>-<started, compact UTC>`, for example
`e1-seeded-pr-nanocode-openai-20261101T120000Z`; the check refuses any
other directory name.

```toml
cell = "E1"                       # E1 | E2 | E3 | E9
case = "seeded-pr"                # one of the cell's cases (below)
harness = "nanocode-openai"       # codex-stock | nanocode-openai | claude-agent-acp | nanocode-anthropic
surface = "cli"                   # cli | rest | mcp: how the run was submitted
# api_auth = "signed-token"       # rest | mcp only: signed-token | loopback-disabled
kata_sha = "<40-hex commit under test>"
kata_tree = "<40-hex tree of kata_sha>"  # git rev-parse <kata_sha>^{tree}
nanocode_rev = "<40-hex nanocode revision kata pins at kata_sha>"  # required on a nanocode harness, optional on a baseline
# vendor_version = "codex-cli <version>"  # baselines only, required: `codex --version` (codex-stock),
#                                         # or `claude-agent-acp --version`'s bare `<version>`, inside the bound environment
model = "gpt-6-luna"              # the pair's model: gpt-6-luna (OpenAI) | claude-sonnet-5-5 (Anthropic)
effort = "medium"                 # the pair's reasoning effort: medium
credential_mode = "subscription"  # subscription | api_key
capsule_network = "offline"       # offline (nanocode) | vendor-egress-only (codex-stock, claude-agent-acp)
started_utc = "2026-11-01T12:00:00Z"
wall_seconds = 412
outcome = "pass"                  # pass | fail | void (an infrastructure failure, not a harness outcome)
outcome_source = "oracle.txt: <what was read, from where>"   # starts with a listed artifact's path and `:`
# void_reason = "controls.txt: <what failed outside the harness>"  # exactly when outcome = "void"; starts like outcome_source
# E3 only:
# settlement = "proven-ambiguous"  # observed: resumed-at-gate | proven-ambiguous | pr-opened-once | other
# settlement_detail = "<what was observed>"   # exactly when settlement = "other"
# E2 pr and refine only (the kit's observed.toml lines, copied verbatim): variant on any outcome, refined on all but void
# variant = "refine-addendum"      # pr: task-only | refine-addendum; refine: refine-cell
# refined = "no"                   # yes | no: observed on pr; "yes" on a refine pass
tokens_recorded = { input = 0, cache_read = 0, cache_write = 0, output = 0 }  # kata's KNOWN part; "unknown" only on a fail or void
unmetered_calls = 0               # every cell: the usage kata does not know (not in tokens_recorded); E1, E2, E9: ledger.py's unknown charges; E3: the issued calls
# unknown_charges = 0             # E3 only, required: ledger.py's unknown charges, one per attempt kata could not meter (e3-finish.py)
tokens_provider = "unavailable: <reason>"   # or the same four counts, read from the provider
cost_recorded = "unavailable"     # unavailable | estimated (codex-stock or nanocode-anthropic under api_key only, with cost_recorded_usd)
cost_provider = "unavailable: <reason>"     # or the provider's figure, "$<amount>"
artifacts = [
  { path = "oracle.txt", what = "<what this file holds>" },
]
```

Every file in the directory is listed in `artifacts`, every listed file
exists, and none is a symbolic link. A run's row links its record and each
artifact, and shows its `outcome_source`. `just evidence-render` rewrites the sections below from the records;
`just evidence-check` refuses a page that differs from that render.

## Parity

Parity is judged per pair, between the pair's two harnesses only: OpenAI
(`nanocode-openai` against `codex-stock`) and Anthropic
(`nanocode-anthropic` against `claude-agent-acp`). A harness of one pair is
never compared with a harness of the other. Parity counts three cases: E1
`seeded-pr`, E1 `public-pr` and E2 `pr`. E2's `mismatch` case is a refusal,
not an implement run, and its `refine` case is the fix loop's proof, one run
per harness (see E2), so neither counts. For each case on each harness,
parity counts the first N non-void runs, in the order they started
(`started_utc`). A later run never replaces an earlier one.

A `void` run is an infrastructure failure, not a harness outcome: a positive
control that did not hold (E3's fault point never reached, the forge or the
host failing under the run), never the harness failing its task, which is a
`fail`. It states what failed in `void_reason`, read from a listed artifact,
does not count, and is shown as void beside the counted runs. It is
replaced by one more run on the SAME surface as the run it voids.

The check refuses a counted round that breaks either of these, since no later
run can repair it (a new round is a new pinned commit, and every harness
re-runs):

- every E1 and E2 parity run and every E2 `refine` run, of both pairs and
  any outcome, is on one `kata_sha`;
- the counted runs of each E1 case on each harness are submitted through the
  CLI or REST and include at least one of each;
- the counted E2 `pr` runs, of both pairs, ran one task `variant` (see E2).
  `refined` is never compared, and the variant of a void run, or of a run
  after the first N, is outside this rule.

The order (run 1 through the CLI, run 2 through REST, run 3 through either)
and replacing a void run on its own surface are the procedure the runs follow to
keep that mix; the check refuses only a counted set without it, and
accepts one in another order that still holds both surfaces.

The round has no notion of an uncounted run: every committed E1 and E2
parity record, and every E2 `refine` record, is in it. A run that validates the kit or the engine rather
than counting (on another commit, or before the round) is never committed
under `runs/`.

A pair's rule is met when:

- every case has N counted runs on each of its harnesses;
- in every case, the pair's nanocode harness passes every assertion in at
  least as many counted runs as its baseline does.

The same model and reasoning effort hold by construction (every record
carries its pair's), and so do the one `kata_sha`, the E1 surface mix and
the one E2 variant (the check refuses a round without them).

Token totals are recorded side by side and are informational, not part of
the rule.

**N is 3, the owner's decision:** three counted runs of each E1 case
(`seeded-pr` and `public-pr`) and three of E2 `pr` on each harness, so nine
per harness and 36 over the two pairs. This page renders it as `PARITY_RUNS` in
`scripts/evidence-page.py`; a change to N changes `PARITY_RUNS` and this
paragraph together.

<!-- evidence:parity:begin -->
**OpenAI pair**: `codex-stock` (baseline) vs `nanocode-openai`, on gpt-6-luna / medium.

| Harness | E1 seeded-pr | E1 public-pr | E2 pr |
|---|---|---|---|
| codex-stock | 1 pass of 3 | 3 pass of 3 | 3 pass of 3 |
| nanocode-openai | 0 pass of 3 | 3 pass of 3 | 3 pass of 3 |

OpenAI parity: not met — nanocode-openai passes fewer counted runs than codex-stock: E1 seeded-pr.

**Anthropic pair**: `claude-agent-acp` (baseline) vs `nanocode-anthropic`, on claude-sonnet-5-5 / medium.

| Harness | E1 seeded-pr | E1 public-pr | E2 pr |
|---|---|---|---|
| claude-agent-acp | 2 pass of 3 | 3 pass of 3 | 3 pass of 3 |
| nanocode-anthropic | not yet run | not yet run | not yet run |

Anthropic parity: not met — fewer than 3 counted runs: nanocode-anthropic E1 seeded-pr; nanocode-anthropic E1 public-pr; nanocode-anthropic E2 pr.
<!-- evidence:parity:end -->

## E1: review a real pull request

`kata run review --target pr:<N>` on two targets: `seeded-pr`, a pull request
on a throwaway repository whose defects were seeded and written down before
the run, and `public-pr`, one real third-party public pull request, read
only. Each harness runs each case until it has N counted (non-void) runs
(see Parity): run 1 through the CLI, run 2 through REST, run 3 through
either.

A run passes when:

- the head kata froze equals the forge's head for the pull request
  (`gh pr view <N> --json headRefOid`);
- the review validates outside kata: its verdict is in the enumeration, each
  finding has a path, a line, a severity and a message, and every path exists
  in `git ls-tree -r <head>`;
- for `seeded-pr`, every seeded defect is matched by a finding with the same
  path and a line inside the seeded range, scored outside kata;
- the remote is unchanged (`git ls-remote` before and after), and no target
  pin is left after the run is terminal;
- tokens and the validation-retry count per stage are read from the
  database into a listed artifact (the row shows the run's token total), and
  the wall time is recorded.

The kit's `e1-run.sh` writes one line per oracle into `oracles.txt`, eight
in all. A non-void E1 run's `outcome_source` reads `oracles.txt: ...`, and
`just evidence-check` refuses one that cites any other artifact; the run is
judged by that file under the E2 rules below (the line shape, the count, and
`pass` exactly when every line is PASS), with no last-oracle rule.

<!-- evidence:E1:begin -->
| Case | codex-stock | nanocode-openai | claude-agent-acp | nanocode-anthropic |
|---|---|---|---|---|
| seeded-pr | 1 pass of 3 run(s) | 0 pass of 3 run(s) | 2 pass of 3 run(s) | not yet run |
| public-pr | 3 pass of 3 run(s) | 3 pass of 3 run(s) | 3 pass of 3 run(s) | not yet run |

| Run | Case | Harness | Surface | kata | Vendor | Model (effort) | Tokens, kata | Tokens, provider | Cost, kata | Cost, provider | Wall | Outcome | Read from | Artifacts |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| [e1-public-pr-claude-agent-acp-20261110T040858Z](runs/e1-public-pr-claude-agent-acp-20261110T040858Z/run.toml) | public-pr | claude-agent-acp | cli | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | claude-agent-acp `0.79.0` | claude-sonnet-5-5 (medium) | in 10 / cached 73585 / cache-write 11263 / out 807 | unavailable: the Anthropic console was not read for the run's window | unavailable | unavailable: the Anthropic console was not read for the run's window | 18 s | **pass** | oracles.txt: 8 of 8 PASS; review-validates-and-scores row: score-e1: ok seeded 0/0 (unmatched 0 of 0 findings) | [after.txt](runs/e1-public-pr-claude-agent-acp-20261110T040858Z/after.txt), [before.txt](runs/e1-public-pr-claude-agent-acp-20261110T040858Z/before.txt), [e1-run.log](runs/e1-public-pr-claude-agent-acp-20261110T040858Z/e1-run.log), [ended_utc](runs/e1-public-pr-claude-agent-acp-20261110T040858Z/ended_utc), [exec](runs/e1-public-pr-claude-agent-acp-20261110T040858Z/exec), [forge-head.txt](runs/e1-public-pr-claude-agent-acp-20261110T040858Z/forge-head.txt), [head.txt](runs/e1-public-pr-claude-agent-acp-20261110T040858Z/head.txt), [oracles.txt](runs/e1-public-pr-claude-agent-acp-20261110T040858Z/oracles.txt), [pins.txt](runs/e1-public-pr-claude-agent-acp-20261110T040858Z/pins.txt), [remote-diff.txt](runs/e1-public-pr-claude-agent-acp-20261110T040858Z/remote-diff.txt), [review.json](runs/e1-public-pr-claude-agent-acp-20261110T040858Z/review.json), [score-row.txt](runs/e1-public-pr-claude-agent-acp-20261110T040858Z/score-row.txt), [score.json](runs/e1-public-pr-claude-agent-acp-20261110T040858Z/score.json), [spend.toml](runs/e1-public-pr-claude-agent-acp-20261110T040858Z/spend.toml), [stages.txt](runs/e1-public-pr-claude-agent-acp-20261110T040858Z/stages.txt), [started_utc](runs/e1-public-pr-claude-agent-acp-20261110T040858Z/started_utc), [submit.json](runs/e1-public-pr-claude-agent-acp-20261110T040858Z/submit.json), [turns.txt](runs/e1-public-pr-claude-agent-acp-20261110T040858Z/turns.txt), [verify-output.json](runs/e1-public-pr-claude-agent-acp-20261110T040858Z/verify-output.json), [wait.json](runs/e1-public-pr-claude-agent-acp-20261110T040858Z/wait.json), [wait.rc](runs/e1-public-pr-claude-agent-acp-20261110T040858Z/wait.rc), [wall_seconds](runs/e1-public-pr-claude-agent-acp-20261110T040858Z/wall_seconds), [watch.txt](runs/e1-public-pr-claude-agent-acp-20261110T040858Z/watch.txt) |
| [e1-public-pr-claude-agent-acp-20261110T040928Z](runs/e1-public-pr-claude-agent-acp-20261110T040928Z/run.toml) | public-pr | claude-agent-acp | rest (loopback-disabled) | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | claude-agent-acp `0.79.0` | claude-sonnet-5-5 (medium) | in 10 / cached 73375 / cache-write 11029 / out 796 | unavailable: the Anthropic console was not read for the run's window | unavailable | unavailable: the Anthropic console was not read for the run's window | 19 s | **pass** | oracles.txt: 8 of 8 PASS; review-validates-and-scores row: score-e1: ok seeded 0/0 (unmatched 0 of 0 findings) | [after.txt](runs/e1-public-pr-claude-agent-acp-20261110T040928Z/after.txt), [before.txt](runs/e1-public-pr-claude-agent-acp-20261110T040928Z/before.txt), [e1-run.log](runs/e1-public-pr-claude-agent-acp-20261110T040928Z/e1-run.log), [ended_utc](runs/e1-public-pr-claude-agent-acp-20261110T040928Z/ended_utc), [exec](runs/e1-public-pr-claude-agent-acp-20261110T040928Z/exec), [forge-head.txt](runs/e1-public-pr-claude-agent-acp-20261110T040928Z/forge-head.txt), [head.txt](runs/e1-public-pr-claude-agent-acp-20261110T040928Z/head.txt), [oracles.txt](runs/e1-public-pr-claude-agent-acp-20261110T040928Z/oracles.txt), [pins.txt](runs/e1-public-pr-claude-agent-acp-20261110T040928Z/pins.txt), [remote-diff.txt](runs/e1-public-pr-claude-agent-acp-20261110T040928Z/remote-diff.txt), [review.json](runs/e1-public-pr-claude-agent-acp-20261110T040928Z/review.json), [score-row.txt](runs/e1-public-pr-claude-agent-acp-20261110T040928Z/score-row.txt), [score.json](runs/e1-public-pr-claude-agent-acp-20261110T040928Z/score.json), [spend.toml](runs/e1-public-pr-claude-agent-acp-20261110T040928Z/spend.toml), [stages.txt](runs/e1-public-pr-claude-agent-acp-20261110T040928Z/stages.txt), [started_utc](runs/e1-public-pr-claude-agent-acp-20261110T040928Z/started_utc), [submit.json](runs/e1-public-pr-claude-agent-acp-20261110T040928Z/submit.json), [turns.txt](runs/e1-public-pr-claude-agent-acp-20261110T040928Z/turns.txt), [verify-output.json](runs/e1-public-pr-claude-agent-acp-20261110T040928Z/verify-output.json), [wait.json](runs/e1-public-pr-claude-agent-acp-20261110T040928Z/wait.json), [wait.rc](runs/e1-public-pr-claude-agent-acp-20261110T040928Z/wait.rc), [wall_seconds](runs/e1-public-pr-claude-agent-acp-20261110T040928Z/wall_seconds) |
| [e1-public-pr-claude-agent-acp-20261110T040958Z](runs/e1-public-pr-claude-agent-acp-20261110T040958Z/run.toml) | public-pr | claude-agent-acp | cli | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | claude-agent-acp `0.79.0` | claude-sonnet-5-5 (medium) | in 12 / cached 90839 / cache-write 11361 / out 830 | unavailable: the Anthropic console was not read for the run's window | unavailable | unavailable: the Anthropic console was not read for the run's window | 23 s | **pass** | oracles.txt: 8 of 8 PASS; review-validates-and-scores row: score-e1: ok seeded 0/0 (unmatched 0 of 0 findings) | [after.txt](runs/e1-public-pr-claude-agent-acp-20261110T040958Z/after.txt), [before.txt](runs/e1-public-pr-claude-agent-acp-20261110T040958Z/before.txt), [e1-run.log](runs/e1-public-pr-claude-agent-acp-20261110T040958Z/e1-run.log), [ended_utc](runs/e1-public-pr-claude-agent-acp-20261110T040958Z/ended_utc), [exec](runs/e1-public-pr-claude-agent-acp-20261110T040958Z/exec), [forge-head.txt](runs/e1-public-pr-claude-agent-acp-20261110T040958Z/forge-head.txt), [head.txt](runs/e1-public-pr-claude-agent-acp-20261110T040958Z/head.txt), [oracles.txt](runs/e1-public-pr-claude-agent-acp-20261110T040958Z/oracles.txt), [pins.txt](runs/e1-public-pr-claude-agent-acp-20261110T040958Z/pins.txt), [remote-diff.txt](runs/e1-public-pr-claude-agent-acp-20261110T040958Z/remote-diff.txt), [review.json](runs/e1-public-pr-claude-agent-acp-20261110T040958Z/review.json), [score-row.txt](runs/e1-public-pr-claude-agent-acp-20261110T040958Z/score-row.txt), [score.json](runs/e1-public-pr-claude-agent-acp-20261110T040958Z/score.json), [spend.toml](runs/e1-public-pr-claude-agent-acp-20261110T040958Z/spend.toml), [stages.txt](runs/e1-public-pr-claude-agent-acp-20261110T040958Z/stages.txt), [started_utc](runs/e1-public-pr-claude-agent-acp-20261110T040958Z/started_utc), [submit.json](runs/e1-public-pr-claude-agent-acp-20261110T040958Z/submit.json), [turns.txt](runs/e1-public-pr-claude-agent-acp-20261110T040958Z/turns.txt), [verify-output.json](runs/e1-public-pr-claude-agent-acp-20261110T040958Z/verify-output.json), [wait.json](runs/e1-public-pr-claude-agent-acp-20261110T040958Z/wait.json), [wait.rc](runs/e1-public-pr-claude-agent-acp-20261110T040958Z/wait.rc), [wall_seconds](runs/e1-public-pr-claude-agent-acp-20261110T040958Z/wall_seconds), [watch.txt](runs/e1-public-pr-claude-agent-acp-20261110T040958Z/watch.txt) |
| [e1-public-pr-codex-stock-20261110T033610Z](runs/e1-public-pr-codex-stock-20261110T033610Z/run.toml) | public-pr | codex-stock | cli | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | codex `codex-cli 0.165.0` | gpt-6-luna (medium) | in 38082 / cached 100992 / cache-write 0 / out 909 | unavailable: a subscription login has no per-token view | unavailable | unavailable: subscription | 30 s | **pass** | oracles.txt: 8 of 8 PASS; review-validates-and-scores row: score-e1: ok seeded 0/0 (unmatched 0 of 0 findings) | [after.txt](runs/e1-public-pr-codex-stock-20261110T033610Z/after.txt), [before.txt](runs/e1-public-pr-codex-stock-20261110T033610Z/before.txt), [e1-run.log](runs/e1-public-pr-codex-stock-20261110T033610Z/e1-run.log), [ended_utc](runs/e1-public-pr-codex-stock-20261110T033610Z/ended_utc), [exec](runs/e1-public-pr-codex-stock-20261110T033610Z/exec), [forge-head.txt](runs/e1-public-pr-codex-stock-20261110T033610Z/forge-head.txt), [head.txt](runs/e1-public-pr-codex-stock-20261110T033610Z/head.txt), [oracles.txt](runs/e1-public-pr-codex-stock-20261110T033610Z/oracles.txt), [pins.txt](runs/e1-public-pr-codex-stock-20261110T033610Z/pins.txt), [remote-diff.txt](runs/e1-public-pr-codex-stock-20261110T033610Z/remote-diff.txt), [review.json](runs/e1-public-pr-codex-stock-20261110T033610Z/review.json), [score-row.txt](runs/e1-public-pr-codex-stock-20261110T033610Z/score-row.txt), [score.json](runs/e1-public-pr-codex-stock-20261110T033610Z/score.json), [spend.toml](runs/e1-public-pr-codex-stock-20261110T033610Z/spend.toml), [stages.txt](runs/e1-public-pr-codex-stock-20261110T033610Z/stages.txt), [started_utc](runs/e1-public-pr-codex-stock-20261110T033610Z/started_utc), [submit.json](runs/e1-public-pr-codex-stock-20261110T033610Z/submit.json), [turns.txt](runs/e1-public-pr-codex-stock-20261110T033610Z/turns.txt), [verify-output.json](runs/e1-public-pr-codex-stock-20261110T033610Z/verify-output.json), [wait.json](runs/e1-public-pr-codex-stock-20261110T033610Z/wait.json), [wait.rc](runs/e1-public-pr-codex-stock-20261110T033610Z/wait.rc), [wall_seconds](runs/e1-public-pr-codex-stock-20261110T033610Z/wall_seconds), [watch.txt](runs/e1-public-pr-codex-stock-20261110T033610Z/watch.txt) |
| [e1-public-pr-codex-stock-20261110T033650Z](runs/e1-public-pr-codex-stock-20261110T033650Z/run.toml) | public-pr | codex-stock | rest (loopback-disabled) | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | codex `codex-cli 0.165.0` | gpt-6-luna (medium) | in 26910 / cached 92288 / cache-write 0 / out 868 | unavailable: a subscription login has no per-token view | unavailable | unavailable: subscription | 30 s | **pass** | oracles.txt: 8 of 8 PASS; review-validates-and-scores row: score-e1: ok seeded 0/0 (unmatched 0 of 0 findings) | [after.txt](runs/e1-public-pr-codex-stock-20261110T033650Z/after.txt), [before.txt](runs/e1-public-pr-codex-stock-20261110T033650Z/before.txt), [e1-run.log](runs/e1-public-pr-codex-stock-20261110T033650Z/e1-run.log), [ended_utc](runs/e1-public-pr-codex-stock-20261110T033650Z/ended_utc), [exec](runs/e1-public-pr-codex-stock-20261110T033650Z/exec), [forge-head.txt](runs/e1-public-pr-codex-stock-20261110T033650Z/forge-head.txt), [head.txt](runs/e1-public-pr-codex-stock-20261110T033650Z/head.txt), [oracles.txt](runs/e1-public-pr-codex-stock-20261110T033650Z/oracles.txt), [pins.txt](runs/e1-public-pr-codex-stock-20261110T033650Z/pins.txt), [remote-diff.txt](runs/e1-public-pr-codex-stock-20261110T033650Z/remote-diff.txt), [review.json](runs/e1-public-pr-codex-stock-20261110T033650Z/review.json), [score-row.txt](runs/e1-public-pr-codex-stock-20261110T033650Z/score-row.txt), [score.json](runs/e1-public-pr-codex-stock-20261110T033650Z/score.json), [spend.toml](runs/e1-public-pr-codex-stock-20261110T033650Z/spend.toml), [stages.txt](runs/e1-public-pr-codex-stock-20261110T033650Z/stages.txt), [started_utc](runs/e1-public-pr-codex-stock-20261110T033650Z/started_utc), [submit.json](runs/e1-public-pr-codex-stock-20261110T033650Z/submit.json), [turns.txt](runs/e1-public-pr-codex-stock-20261110T033650Z/turns.txt), [verify-output.json](runs/e1-public-pr-codex-stock-20261110T033650Z/verify-output.json), [wait.json](runs/e1-public-pr-codex-stock-20261110T033650Z/wait.json), [wait.rc](runs/e1-public-pr-codex-stock-20261110T033650Z/wait.rc), [wall_seconds](runs/e1-public-pr-codex-stock-20261110T033650Z/wall_seconds) |
| [e1-public-pr-codex-stock-20261110T033730Z](runs/e1-public-pr-codex-stock-20261110T033730Z/run.toml) | public-pr | codex-stock | cli | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | codex `codex-cli 0.165.0` | gpt-6-luna (medium) | in 50512 / cached 49152 / cache-write 0 / out 712 | unavailable: a subscription login has no per-token view | unavailable | unavailable: subscription | 29 s | **pass** | oracles.txt: 8 of 8 PASS; review-validates-and-scores row: score-e1: ok seeded 0/0 (unmatched 0 of 0 findings) | [after.txt](runs/e1-public-pr-codex-stock-20261110T033730Z/after.txt), [before.txt](runs/e1-public-pr-codex-stock-20261110T033730Z/before.txt), [e1-run.log](runs/e1-public-pr-codex-stock-20261110T033730Z/e1-run.log), [ended_utc](runs/e1-public-pr-codex-stock-20261110T033730Z/ended_utc), [exec](runs/e1-public-pr-codex-stock-20261110T033730Z/exec), [forge-head.txt](runs/e1-public-pr-codex-stock-20261110T033730Z/forge-head.txt), [head.txt](runs/e1-public-pr-codex-stock-20261110T033730Z/head.txt), [oracles.txt](runs/e1-public-pr-codex-stock-20261110T033730Z/oracles.txt), [pins.txt](runs/e1-public-pr-codex-stock-20261110T033730Z/pins.txt), [remote-diff.txt](runs/e1-public-pr-codex-stock-20261110T033730Z/remote-diff.txt), [review.json](runs/e1-public-pr-codex-stock-20261110T033730Z/review.json), [score-row.txt](runs/e1-public-pr-codex-stock-20261110T033730Z/score-row.txt), [score.json](runs/e1-public-pr-codex-stock-20261110T033730Z/score.json), [spend.toml](runs/e1-public-pr-codex-stock-20261110T033730Z/spend.toml), [stages.txt](runs/e1-public-pr-codex-stock-20261110T033730Z/stages.txt), [started_utc](runs/e1-public-pr-codex-stock-20261110T033730Z/started_utc), [submit.json](runs/e1-public-pr-codex-stock-20261110T033730Z/submit.json), [turns.txt](runs/e1-public-pr-codex-stock-20261110T033730Z/turns.txt), [verify-output.json](runs/e1-public-pr-codex-stock-20261110T033730Z/verify-output.json), [wait.json](runs/e1-public-pr-codex-stock-20261110T033730Z/wait.json), [wait.rc](runs/e1-public-pr-codex-stock-20261110T033730Z/wait.rc), [wall_seconds](runs/e1-public-pr-codex-stock-20261110T033730Z/wall_seconds), [watch.txt](runs/e1-public-pr-codex-stock-20261110T033730Z/watch.txt) |
| [e1-public-pr-nanocode-openai-20261110T022230Z](runs/e1-public-pr-nanocode-openai-20261110T022230Z/run.toml) | public-pr | nanocode-openai | cli | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | nanocode `2ac77424e032` | gpt-6-luna (medium) | in 34641 / cached 29184 / cache-write 0 / out 828 | unavailable: a subscription login has no per-token view | unavailable | unavailable: subscription | 43 s | **pass** | oracles.txt: 8 of 8 PASS; review-validates-and-scores row: score-e1: ok seeded 0/0 (unmatched 0 of 0 findings) | [after.txt](runs/e1-public-pr-nanocode-openai-20261110T022230Z/after.txt), [before.txt](runs/e1-public-pr-nanocode-openai-20261110T022230Z/before.txt), [e1-run.log](runs/e1-public-pr-nanocode-openai-20261110T022230Z/e1-run.log), [ended_utc](runs/e1-public-pr-nanocode-openai-20261110T022230Z/ended_utc), [exec](runs/e1-public-pr-nanocode-openai-20261110T022230Z/exec), [forge-head.txt](runs/e1-public-pr-nanocode-openai-20261110T022230Z/forge-head.txt), [head.txt](runs/e1-public-pr-nanocode-openai-20261110T022230Z/head.txt), [oracles.txt](runs/e1-public-pr-nanocode-openai-20261110T022230Z/oracles.txt), [pins.txt](runs/e1-public-pr-nanocode-openai-20261110T022230Z/pins.txt), [remote-diff.txt](runs/e1-public-pr-nanocode-openai-20261110T022230Z/remote-diff.txt), [review.json](runs/e1-public-pr-nanocode-openai-20261110T022230Z/review.json), [score-row.txt](runs/e1-public-pr-nanocode-openai-20261110T022230Z/score-row.txt), [score.json](runs/e1-public-pr-nanocode-openai-20261110T022230Z/score.json), [spend.toml](runs/e1-public-pr-nanocode-openai-20261110T022230Z/spend.toml), [stages.txt](runs/e1-public-pr-nanocode-openai-20261110T022230Z/stages.txt), [started_utc](runs/e1-public-pr-nanocode-openai-20261110T022230Z/started_utc), [submit.json](runs/e1-public-pr-nanocode-openai-20261110T022230Z/submit.json), [turns.txt](runs/e1-public-pr-nanocode-openai-20261110T022230Z/turns.txt), [verify-output.json](runs/e1-public-pr-nanocode-openai-20261110T022230Z/verify-output.json), [wait.json](runs/e1-public-pr-nanocode-openai-20261110T022230Z/wait.json), [wait.rc](runs/e1-public-pr-nanocode-openai-20261110T022230Z/wait.rc), [wall_seconds](runs/e1-public-pr-nanocode-openai-20261110T022230Z/wall_seconds), [watch.txt](runs/e1-public-pr-nanocode-openai-20261110T022230Z/watch.txt) |
| [e1-public-pr-nanocode-openai-20261110T022323Z](runs/e1-public-pr-nanocode-openai-20261110T022323Z/run.toml) | public-pr | nanocode-openai | rest (loopback-disabled) | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | nanocode `2ac77424e032` | gpt-6-luna (medium) | in 22374 / cached 61056 / cache-write 0 / out 979 | unavailable: a subscription login has no per-token view | unavailable | unavailable: subscription | 64 s | **pass** | oracles.txt: 8 of 8 PASS; review-validates-and-scores row: score-e1: ok seeded 0/0 (unmatched 0 of 0 findings) | [after.txt](runs/e1-public-pr-nanocode-openai-20261110T022323Z/after.txt), [before.txt](runs/e1-public-pr-nanocode-openai-20261110T022323Z/before.txt), [e1-run.log](runs/e1-public-pr-nanocode-openai-20261110T022323Z/e1-run.log), [ended_utc](runs/e1-public-pr-nanocode-openai-20261110T022323Z/ended_utc), [exec](runs/e1-public-pr-nanocode-openai-20261110T022323Z/exec), [forge-head.txt](runs/e1-public-pr-nanocode-openai-20261110T022323Z/forge-head.txt), [head.txt](runs/e1-public-pr-nanocode-openai-20261110T022323Z/head.txt), [oracles.txt](runs/e1-public-pr-nanocode-openai-20261110T022323Z/oracles.txt), [pins.txt](runs/e1-public-pr-nanocode-openai-20261110T022323Z/pins.txt), [remote-diff.txt](runs/e1-public-pr-nanocode-openai-20261110T022323Z/remote-diff.txt), [review.json](runs/e1-public-pr-nanocode-openai-20261110T022323Z/review.json), [score-row.txt](runs/e1-public-pr-nanocode-openai-20261110T022323Z/score-row.txt), [score.json](runs/e1-public-pr-nanocode-openai-20261110T022323Z/score.json), [spend.toml](runs/e1-public-pr-nanocode-openai-20261110T022323Z/spend.toml), [stages.txt](runs/e1-public-pr-nanocode-openai-20261110T022323Z/stages.txt), [started_utc](runs/e1-public-pr-nanocode-openai-20261110T022323Z/started_utc), [submit.json](runs/e1-public-pr-nanocode-openai-20261110T022323Z/submit.json), [turns.txt](runs/e1-public-pr-nanocode-openai-20261110T022323Z/turns.txt), [verify-output.json](runs/e1-public-pr-nanocode-openai-20261110T022323Z/verify-output.json), [wait.json](runs/e1-public-pr-nanocode-openai-20261110T022323Z/wait.json), [wait.rc](runs/e1-public-pr-nanocode-openai-20261110T022323Z/wait.rc), [wall_seconds](runs/e1-public-pr-nanocode-openai-20261110T022323Z/wall_seconds) |
| [e1-public-pr-nanocode-openai-20261110T022432Z](runs/e1-public-pr-nanocode-openai-20261110T022432Z/run.toml) | public-pr | nanocode-openai | cli | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | nanocode `2ac77424e032` | gpt-6-luna (medium) | in 30575 / cached 47232 / cache-write 0 / out 889 | unavailable: a subscription login has no per-token view | unavailable | unavailable: subscription | 38 s | **pass** | oracles.txt: 8 of 8 PASS; review-validates-and-scores row: score-e1: ok seeded 0/0 (unmatched 0 of 0 findings) | [after.txt](runs/e1-public-pr-nanocode-openai-20261110T022432Z/after.txt), [before.txt](runs/e1-public-pr-nanocode-openai-20261110T022432Z/before.txt), [e1-run.log](runs/e1-public-pr-nanocode-openai-20261110T022432Z/e1-run.log), [ended_utc](runs/e1-public-pr-nanocode-openai-20261110T022432Z/ended_utc), [exec](runs/e1-public-pr-nanocode-openai-20261110T022432Z/exec), [forge-head.txt](runs/e1-public-pr-nanocode-openai-20261110T022432Z/forge-head.txt), [head.txt](runs/e1-public-pr-nanocode-openai-20261110T022432Z/head.txt), [oracles.txt](runs/e1-public-pr-nanocode-openai-20261110T022432Z/oracles.txt), [pins.txt](runs/e1-public-pr-nanocode-openai-20261110T022432Z/pins.txt), [remote-diff.txt](runs/e1-public-pr-nanocode-openai-20261110T022432Z/remote-diff.txt), [review.json](runs/e1-public-pr-nanocode-openai-20261110T022432Z/review.json), [score-row.txt](runs/e1-public-pr-nanocode-openai-20261110T022432Z/score-row.txt), [score.json](runs/e1-public-pr-nanocode-openai-20261110T022432Z/score.json), [spend.toml](runs/e1-public-pr-nanocode-openai-20261110T022432Z/spend.toml), [stages.txt](runs/e1-public-pr-nanocode-openai-20261110T022432Z/stages.txt), [started_utc](runs/e1-public-pr-nanocode-openai-20261110T022432Z/started_utc), [submit.json](runs/e1-public-pr-nanocode-openai-20261110T022432Z/submit.json), [turns.txt](runs/e1-public-pr-nanocode-openai-20261110T022432Z/turns.txt), [verify-output.json](runs/e1-public-pr-nanocode-openai-20261110T022432Z/verify-output.json), [wait.json](runs/e1-public-pr-nanocode-openai-20261110T022432Z/wait.json), [wait.rc](runs/e1-public-pr-nanocode-openai-20261110T022432Z/wait.rc), [wall_seconds](runs/e1-public-pr-nanocode-openai-20261110T022432Z/wall_seconds), [watch.txt](runs/e1-public-pr-nanocode-openai-20261110T022432Z/watch.txt) |
| [e1-seeded-pr-claude-agent-acp-20261110T040612Z](runs/e1-seeded-pr-claude-agent-acp-20261110T040612Z/run.toml) | seeded-pr | claude-agent-acp | cli | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | claude-agent-acp `0.79.0` | claude-sonnet-5-5 (medium) | in 8 / cached 54769 / cache-write 13482 / out 1818 | unavailable: the Anthropic console was not read for the run's window | unavailable | unavailable: the Anthropic console was not read for the run's window | 22 s | **fail** | oracles.txt: 7 of 8 PASS; FAIL review-validates-and-scores: score-e1: FAIL seeded 2/3 (unmatched 2 of 4 findings) | [after.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040612Z/after.txt), [before.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040612Z/before.txt), [e1-run.log](runs/e1-seeded-pr-claude-agent-acp-20261110T040612Z/e1-run.log), [ended_utc](runs/e1-seeded-pr-claude-agent-acp-20261110T040612Z/ended_utc), [exec](runs/e1-seeded-pr-claude-agent-acp-20261110T040612Z/exec), [forge-head.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040612Z/forge-head.txt), [head.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040612Z/head.txt), [oracles.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040612Z/oracles.txt), [pins.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040612Z/pins.txt), [remote-diff.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040612Z/remote-diff.txt), [review.json](runs/e1-seeded-pr-claude-agent-acp-20261110T040612Z/review.json), [score-row.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040612Z/score-row.txt), [score.json](runs/e1-seeded-pr-claude-agent-acp-20261110T040612Z/score.json), [spend.toml](runs/e1-seeded-pr-claude-agent-acp-20261110T040612Z/spend.toml), [stages.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040612Z/stages.txt), [started_utc](runs/e1-seeded-pr-claude-agent-acp-20261110T040612Z/started_utc), [submit.json](runs/e1-seeded-pr-claude-agent-acp-20261110T040612Z/submit.json), [turns.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040612Z/turns.txt), [verify-output.json](runs/e1-seeded-pr-claude-agent-acp-20261110T040612Z/verify-output.json), [wait.json](runs/e1-seeded-pr-claude-agent-acp-20261110T040612Z/wait.json), [wait.rc](runs/e1-seeded-pr-claude-agent-acp-20261110T040612Z/wait.rc), [wall_seconds](runs/e1-seeded-pr-claude-agent-acp-20261110T040612Z/wall_seconds), [watch.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040612Z/watch.txt) |
| [e1-seeded-pr-claude-agent-acp-20261110T040648Z](runs/e1-seeded-pr-claude-agent-acp-20261110T040648Z/run.toml) | seeded-pr | claude-agent-acp | rest (loopback-disabled) | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | claude-agent-acp `0.79.0` | claude-sonnet-5-5 (medium) | in 8 / cached 56234 / cache-write 12955 / out 1653 | unavailable: the Anthropic console was not read for the run's window | unavailable | unavailable: the Anthropic console was not read for the run's window | 23 s | **pass** | oracles.txt: 8 of 8 PASS; review-validates-and-scores row: score-e1: ok seeded 3/3 (unmatched 1 of 4 findings) | [after.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040648Z/after.txt), [before.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040648Z/before.txt), [e1-run.log](runs/e1-seeded-pr-claude-agent-acp-20261110T040648Z/e1-run.log), [ended_utc](runs/e1-seeded-pr-claude-agent-acp-20261110T040648Z/ended_utc), [exec](runs/e1-seeded-pr-claude-agent-acp-20261110T040648Z/exec), [forge-head.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040648Z/forge-head.txt), [head.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040648Z/head.txt), [oracles.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040648Z/oracles.txt), [pins.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040648Z/pins.txt), [remote-diff.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040648Z/remote-diff.txt), [review.json](runs/e1-seeded-pr-claude-agent-acp-20261110T040648Z/review.json), [score-row.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040648Z/score-row.txt), [score.json](runs/e1-seeded-pr-claude-agent-acp-20261110T040648Z/score.json), [spend.toml](runs/e1-seeded-pr-claude-agent-acp-20261110T040648Z/spend.toml), [stages.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040648Z/stages.txt), [started_utc](runs/e1-seeded-pr-claude-agent-acp-20261110T040648Z/started_utc), [submit.json](runs/e1-seeded-pr-claude-agent-acp-20261110T040648Z/submit.json), [turns.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040648Z/turns.txt), [verify-output.json](runs/e1-seeded-pr-claude-agent-acp-20261110T040648Z/verify-output.json), [wait.json](runs/e1-seeded-pr-claude-agent-acp-20261110T040648Z/wait.json), [wait.rc](runs/e1-seeded-pr-claude-agent-acp-20261110T040648Z/wait.rc), [wall_seconds](runs/e1-seeded-pr-claude-agent-acp-20261110T040648Z/wall_seconds) |
| [e1-seeded-pr-claude-agent-acp-20261110T040719Z](runs/e1-seeded-pr-claude-agent-acp-20261110T040719Z/run.toml) | seeded-pr | claude-agent-acp | cli | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | claude-agent-acp `0.79.0` | claude-sonnet-5-5 (medium) | in 14 / cached 101845 / cache-write 18205 / out 2143 | unavailable: the Anthropic console was not read for the run's window | unavailable | unavailable: the Anthropic console was not read for the run's window | 29 s | **pass** | oracles.txt: 8 of 8 PASS; review-validates-and-scores row: score-e1: ok seeded 3/3 (unmatched 1 of 4 findings) | [after.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040719Z/after.txt), [before.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040719Z/before.txt), [e1-run.log](runs/e1-seeded-pr-claude-agent-acp-20261110T040719Z/e1-run.log), [ended_utc](runs/e1-seeded-pr-claude-agent-acp-20261110T040719Z/ended_utc), [exec](runs/e1-seeded-pr-claude-agent-acp-20261110T040719Z/exec), [forge-head.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040719Z/forge-head.txt), [head.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040719Z/head.txt), [oracles.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040719Z/oracles.txt), [pins.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040719Z/pins.txt), [remote-diff.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040719Z/remote-diff.txt), [review.json](runs/e1-seeded-pr-claude-agent-acp-20261110T040719Z/review.json), [score-row.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040719Z/score-row.txt), [score.json](runs/e1-seeded-pr-claude-agent-acp-20261110T040719Z/score.json), [spend.toml](runs/e1-seeded-pr-claude-agent-acp-20261110T040719Z/spend.toml), [stages.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040719Z/stages.txt), [started_utc](runs/e1-seeded-pr-claude-agent-acp-20261110T040719Z/started_utc), [submit.json](runs/e1-seeded-pr-claude-agent-acp-20261110T040719Z/submit.json), [turns.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040719Z/turns.txt), [verify-output.json](runs/e1-seeded-pr-claude-agent-acp-20261110T040719Z/verify-output.json), [wait.json](runs/e1-seeded-pr-claude-agent-acp-20261110T040719Z/wait.json), [wait.rc](runs/e1-seeded-pr-claude-agent-acp-20261110T040719Z/wait.rc), [wall_seconds](runs/e1-seeded-pr-claude-agent-acp-20261110T040719Z/wall_seconds), [watch.txt](runs/e1-seeded-pr-claude-agent-acp-20261110T040719Z/watch.txt) |
| [e1-seeded-pr-codex-stock-20261110T033212Z](runs/e1-seeded-pr-codex-stock-20261110T033212Z/run.toml) | seeded-pr | codex-stock | cli | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | codex `codex-cli 0.165.0` | gpt-6-luna (medium) | in 52889 / cached 61184 / cache-write 0 / out 948 | unavailable: a subscription login has no per-token view | unavailable | unavailable: subscription | 56 s | **fail** | oracles.txt: 7 of 8 PASS; FAIL review-validates-and-scores: score-e1: FAIL seeded 2/3 (unmatched 0 of 2 findings) | [after.txt](runs/e1-seeded-pr-codex-stock-20261110T033212Z/after.txt), [before.txt](runs/e1-seeded-pr-codex-stock-20261110T033212Z/before.txt), [e1-run.log](runs/e1-seeded-pr-codex-stock-20261110T033212Z/e1-run.log), [ended_utc](runs/e1-seeded-pr-codex-stock-20261110T033212Z/ended_utc), [exec](runs/e1-seeded-pr-codex-stock-20261110T033212Z/exec), [forge-head.txt](runs/e1-seeded-pr-codex-stock-20261110T033212Z/forge-head.txt), [head.txt](runs/e1-seeded-pr-codex-stock-20261110T033212Z/head.txt), [oracles.txt](runs/e1-seeded-pr-codex-stock-20261110T033212Z/oracles.txt), [pins.txt](runs/e1-seeded-pr-codex-stock-20261110T033212Z/pins.txt), [remote-diff.txt](runs/e1-seeded-pr-codex-stock-20261110T033212Z/remote-diff.txt), [review.json](runs/e1-seeded-pr-codex-stock-20261110T033212Z/review.json), [score-row.txt](runs/e1-seeded-pr-codex-stock-20261110T033212Z/score-row.txt), [score.json](runs/e1-seeded-pr-codex-stock-20261110T033212Z/score.json), [spend.toml](runs/e1-seeded-pr-codex-stock-20261110T033212Z/spend.toml), [stages.txt](runs/e1-seeded-pr-codex-stock-20261110T033212Z/stages.txt), [started_utc](runs/e1-seeded-pr-codex-stock-20261110T033212Z/started_utc), [submit.json](runs/e1-seeded-pr-codex-stock-20261110T033212Z/submit.json), [turns.txt](runs/e1-seeded-pr-codex-stock-20261110T033212Z/turns.txt), [verify-output.json](runs/e1-seeded-pr-codex-stock-20261110T033212Z/verify-output.json), [wait.json](runs/e1-seeded-pr-codex-stock-20261110T033212Z/wait.json), [wait.rc](runs/e1-seeded-pr-codex-stock-20261110T033212Z/wait.rc), [wall_seconds](runs/e1-seeded-pr-codex-stock-20261110T033212Z/wall_seconds), [watch.txt](runs/e1-seeded-pr-codex-stock-20261110T033212Z/watch.txt) |
| [e1-seeded-pr-codex-stock-20261110T033327Z](runs/e1-seeded-pr-codex-stock-20261110T033327Z/run.toml) | seeded-pr | codex-stock | rest (loopback-disabled) | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | codex `codex-cli 0.165.0` | gpt-6-luna (medium) | in 35512 / cached 45568 / cache-write 0 / out 1086 | unavailable: a subscription login has no per-token view | unavailable | unavailable: subscription | 32 s | **pass** | oracles.txt: 8 of 8 PASS; review-validates-and-scores row: score-e1: ok seeded 3/3 (unmatched 0 of 3 findings) | [after.txt](runs/e1-seeded-pr-codex-stock-20261110T033327Z/after.txt), [before.txt](runs/e1-seeded-pr-codex-stock-20261110T033327Z/before.txt), [e1-run.log](runs/e1-seeded-pr-codex-stock-20261110T033327Z/e1-run.log), [ended_utc](runs/e1-seeded-pr-codex-stock-20261110T033327Z/ended_utc), [exec](runs/e1-seeded-pr-codex-stock-20261110T033327Z/exec), [forge-head.txt](runs/e1-seeded-pr-codex-stock-20261110T033327Z/forge-head.txt), [head.txt](runs/e1-seeded-pr-codex-stock-20261110T033327Z/head.txt), [oracles.txt](runs/e1-seeded-pr-codex-stock-20261110T033327Z/oracles.txt), [pins.txt](runs/e1-seeded-pr-codex-stock-20261110T033327Z/pins.txt), [remote-diff.txt](runs/e1-seeded-pr-codex-stock-20261110T033327Z/remote-diff.txt), [review.json](runs/e1-seeded-pr-codex-stock-20261110T033327Z/review.json), [score-row.txt](runs/e1-seeded-pr-codex-stock-20261110T033327Z/score-row.txt), [score.json](runs/e1-seeded-pr-codex-stock-20261110T033327Z/score.json), [spend.toml](runs/e1-seeded-pr-codex-stock-20261110T033327Z/spend.toml), [stages.txt](runs/e1-seeded-pr-codex-stock-20261110T033327Z/stages.txt), [started_utc](runs/e1-seeded-pr-codex-stock-20261110T033327Z/started_utc), [submit.json](runs/e1-seeded-pr-codex-stock-20261110T033327Z/submit.json), [turns.txt](runs/e1-seeded-pr-codex-stock-20261110T033327Z/turns.txt), [verify-output.json](runs/e1-seeded-pr-codex-stock-20261110T033327Z/verify-output.json), [wait.json](runs/e1-seeded-pr-codex-stock-20261110T033327Z/wait.json), [wait.rc](runs/e1-seeded-pr-codex-stock-20261110T033327Z/wait.rc), [wall_seconds](runs/e1-seeded-pr-codex-stock-20261110T033327Z/wall_seconds) |
| [e1-seeded-pr-codex-stock-20261110T033417Z](runs/e1-seeded-pr-codex-stock-20261110T033417Z/run.toml) | seeded-pr | codex-stock | cli | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | codex `codex-cli 0.165.0` | gpt-6-luna (medium) | in 34739 / cached 45440 / cache-write 0 / out 984 | unavailable: a subscription login has no per-token view | unavailable | unavailable: subscription | 32 s | **fail** | oracles.txt: 7 of 8 PASS; FAIL review-validates-and-scores: score-e1: FAIL seeded 2/3 (unmatched 0 of 2 findings) | [after.txt](runs/e1-seeded-pr-codex-stock-20261110T033417Z/after.txt), [before.txt](runs/e1-seeded-pr-codex-stock-20261110T033417Z/before.txt), [e1-run.log](runs/e1-seeded-pr-codex-stock-20261110T033417Z/e1-run.log), [ended_utc](runs/e1-seeded-pr-codex-stock-20261110T033417Z/ended_utc), [exec](runs/e1-seeded-pr-codex-stock-20261110T033417Z/exec), [forge-head.txt](runs/e1-seeded-pr-codex-stock-20261110T033417Z/forge-head.txt), [head.txt](runs/e1-seeded-pr-codex-stock-20261110T033417Z/head.txt), [oracles.txt](runs/e1-seeded-pr-codex-stock-20261110T033417Z/oracles.txt), [pins.txt](runs/e1-seeded-pr-codex-stock-20261110T033417Z/pins.txt), [remote-diff.txt](runs/e1-seeded-pr-codex-stock-20261110T033417Z/remote-diff.txt), [review.json](runs/e1-seeded-pr-codex-stock-20261110T033417Z/review.json), [score-row.txt](runs/e1-seeded-pr-codex-stock-20261110T033417Z/score-row.txt), [score.json](runs/e1-seeded-pr-codex-stock-20261110T033417Z/score.json), [spend.toml](runs/e1-seeded-pr-codex-stock-20261110T033417Z/spend.toml), [stages.txt](runs/e1-seeded-pr-codex-stock-20261110T033417Z/stages.txt), [started_utc](runs/e1-seeded-pr-codex-stock-20261110T033417Z/started_utc), [submit.json](runs/e1-seeded-pr-codex-stock-20261110T033417Z/submit.json), [turns.txt](runs/e1-seeded-pr-codex-stock-20261110T033417Z/turns.txt), [verify-output.json](runs/e1-seeded-pr-codex-stock-20261110T033417Z/verify-output.json), [wait.json](runs/e1-seeded-pr-codex-stock-20261110T033417Z/wait.json), [wait.rc](runs/e1-seeded-pr-codex-stock-20261110T033417Z/wait.rc), [wall_seconds](runs/e1-seeded-pr-codex-stock-20261110T033417Z/wall_seconds), [watch.txt](runs/e1-seeded-pr-codex-stock-20261110T033417Z/watch.txt) |
| [e1-seeded-pr-nanocode-openai-20261110T021905Z](runs/e1-seeded-pr-nanocode-openai-20261110T021905Z/run.toml) | seeded-pr | nanocode-openai | cli | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | nanocode `2ac77424e032` | gpt-6-luna (medium) | in 20760 / cached 40704 / cache-write 0 / out 1125 | unavailable: a subscription login has no per-token view | unavailable | unavailable: subscription | 57 s | **fail** | oracles.txt: 7 of 8 PASS; FAIL review-validates-and-scores: score-e1: FAIL seeded 2/3 (unmatched 0 of 2 findings) | [after.txt](runs/e1-seeded-pr-nanocode-openai-20261110T021905Z/after.txt), [before.txt](runs/e1-seeded-pr-nanocode-openai-20261110T021905Z/before.txt), [e1-run.log](runs/e1-seeded-pr-nanocode-openai-20261110T021905Z/e1-run.log), [ended_utc](runs/e1-seeded-pr-nanocode-openai-20261110T021905Z/ended_utc), [exec](runs/e1-seeded-pr-nanocode-openai-20261110T021905Z/exec), [forge-head.txt](runs/e1-seeded-pr-nanocode-openai-20261110T021905Z/forge-head.txt), [head.txt](runs/e1-seeded-pr-nanocode-openai-20261110T021905Z/head.txt), [oracles.txt](runs/e1-seeded-pr-nanocode-openai-20261110T021905Z/oracles.txt), [pins.txt](runs/e1-seeded-pr-nanocode-openai-20261110T021905Z/pins.txt), [remote-diff.txt](runs/e1-seeded-pr-nanocode-openai-20261110T021905Z/remote-diff.txt), [review.json](runs/e1-seeded-pr-nanocode-openai-20261110T021905Z/review.json), [score-row.txt](runs/e1-seeded-pr-nanocode-openai-20261110T021905Z/score-row.txt), [score.json](runs/e1-seeded-pr-nanocode-openai-20261110T021905Z/score.json), [spend.toml](runs/e1-seeded-pr-nanocode-openai-20261110T021905Z/spend.toml), [stages.txt](runs/e1-seeded-pr-nanocode-openai-20261110T021905Z/stages.txt), [started_utc](runs/e1-seeded-pr-nanocode-openai-20261110T021905Z/started_utc), [submit.json](runs/e1-seeded-pr-nanocode-openai-20261110T021905Z/submit.json), [turns.txt](runs/e1-seeded-pr-nanocode-openai-20261110T021905Z/turns.txt), [verify-output.json](runs/e1-seeded-pr-nanocode-openai-20261110T021905Z/verify-output.json), [wait.json](runs/e1-seeded-pr-nanocode-openai-20261110T021905Z/wait.json), [wait.rc](runs/e1-seeded-pr-nanocode-openai-20261110T021905Z/wait.rc), [wall_seconds](runs/e1-seeded-pr-nanocode-openai-20261110T021905Z/wall_seconds), [watch.txt](runs/e1-seeded-pr-nanocode-openai-20261110T021905Z/watch.txt) |
| [e1-seeded-pr-nanocode-openai-20261110T022011Z](runs/e1-seeded-pr-nanocode-openai-20261110T022011Z/run.toml) | seeded-pr | nanocode-openai | rest (loopback-disabled) | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | nanocode `2ac77424e032` | gpt-6-luna (medium) | in 27169 / cached 14080 / cache-write 0 / out 861 | unavailable: a subscription login has no per-token view | unavailable | unavailable: subscription | 36 s | **fail** | oracles.txt: 7 of 8 PASS; FAIL review-validates-and-scores: score-e1: FAIL seeded 2/3 (unmatched 0 of 2 findings) | [after.txt](runs/e1-seeded-pr-nanocode-openai-20261110T022011Z/after.txt), [before.txt](runs/e1-seeded-pr-nanocode-openai-20261110T022011Z/before.txt), [e1-run.log](runs/e1-seeded-pr-nanocode-openai-20261110T022011Z/e1-run.log), [ended_utc](runs/e1-seeded-pr-nanocode-openai-20261110T022011Z/ended_utc), [exec](runs/e1-seeded-pr-nanocode-openai-20261110T022011Z/exec), [forge-head.txt](runs/e1-seeded-pr-nanocode-openai-20261110T022011Z/forge-head.txt), [head.txt](runs/e1-seeded-pr-nanocode-openai-20261110T022011Z/head.txt), [oracles.txt](runs/e1-seeded-pr-nanocode-openai-20261110T022011Z/oracles.txt), [pins.txt](runs/e1-seeded-pr-nanocode-openai-20261110T022011Z/pins.txt), [remote-diff.txt](runs/e1-seeded-pr-nanocode-openai-20261110T022011Z/remote-diff.txt), [review.json](runs/e1-seeded-pr-nanocode-openai-20261110T022011Z/review.json), [score-row.txt](runs/e1-seeded-pr-nanocode-openai-20261110T022011Z/score-row.txt), [score.json](runs/e1-seeded-pr-nanocode-openai-20261110T022011Z/score.json), [spend.toml](runs/e1-seeded-pr-nanocode-openai-20261110T022011Z/spend.toml), [stages.txt](runs/e1-seeded-pr-nanocode-openai-20261110T022011Z/stages.txt), [started_utc](runs/e1-seeded-pr-nanocode-openai-20261110T022011Z/started_utc), [submit.json](runs/e1-seeded-pr-nanocode-openai-20261110T022011Z/submit.json), [turns.txt](runs/e1-seeded-pr-nanocode-openai-20261110T022011Z/turns.txt), [verify-output.json](runs/e1-seeded-pr-nanocode-openai-20261110T022011Z/verify-output.json), [wait.json](runs/e1-seeded-pr-nanocode-openai-20261110T022011Z/wait.json), [wait.rc](runs/e1-seeded-pr-nanocode-openai-20261110T022011Z/wait.rc), [wall_seconds](runs/e1-seeded-pr-nanocode-openai-20261110T022011Z/wall_seconds) |
| [e1-seeded-pr-nanocode-openai-20261110T022054Z](runs/e1-seeded-pr-nanocode-openai-20261110T022054Z/run.toml) | seeded-pr | nanocode-openai | cli | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | nanocode `2ac77424e032` | gpt-6-luna (medium) | in 24732 / cached 6912 / cache-write 0 / out 754 | unavailable: a subscription login has no per-token view | unavailable | unavailable: subscription | 21 s | **fail** | oracles.txt: 7 of 8 PASS; FAIL review-validates-and-scores: score-e1: FAIL seeded 1/3 (unmatched 1 of 2 findings) | [after.txt](runs/e1-seeded-pr-nanocode-openai-20261110T022054Z/after.txt), [before.txt](runs/e1-seeded-pr-nanocode-openai-20261110T022054Z/before.txt), [e1-run.log](runs/e1-seeded-pr-nanocode-openai-20261110T022054Z/e1-run.log), [ended_utc](runs/e1-seeded-pr-nanocode-openai-20261110T022054Z/ended_utc), [exec](runs/e1-seeded-pr-nanocode-openai-20261110T022054Z/exec), [forge-head.txt](runs/e1-seeded-pr-nanocode-openai-20261110T022054Z/forge-head.txt), [head.txt](runs/e1-seeded-pr-nanocode-openai-20261110T022054Z/head.txt), [oracles.txt](runs/e1-seeded-pr-nanocode-openai-20261110T022054Z/oracles.txt), [pins.txt](runs/e1-seeded-pr-nanocode-openai-20261110T022054Z/pins.txt), [remote-diff.txt](runs/e1-seeded-pr-nanocode-openai-20261110T022054Z/remote-diff.txt), [review.json](runs/e1-seeded-pr-nanocode-openai-20261110T022054Z/review.json), [score-row.txt](runs/e1-seeded-pr-nanocode-openai-20261110T022054Z/score-row.txt), [score.json](runs/e1-seeded-pr-nanocode-openai-20261110T022054Z/score.json), [spend.toml](runs/e1-seeded-pr-nanocode-openai-20261110T022054Z/spend.toml), [stages.txt](runs/e1-seeded-pr-nanocode-openai-20261110T022054Z/stages.txt), [started_utc](runs/e1-seeded-pr-nanocode-openai-20261110T022054Z/started_utc), [submit.json](runs/e1-seeded-pr-nanocode-openai-20261110T022054Z/submit.json), [turns.txt](runs/e1-seeded-pr-nanocode-openai-20261110T022054Z/turns.txt), [verify-output.json](runs/e1-seeded-pr-nanocode-openai-20261110T022054Z/verify-output.json), [wait.json](runs/e1-seeded-pr-nanocode-openai-20261110T022054Z/wait.json), [wait.rc](runs/e1-seeded-pr-nanocode-openai-20261110T022054Z/wait.rc), [wall_seconds](runs/e1-seeded-pr-nanocode-openai-20261110T022054Z/wall_seconds), [watch.txt](runs/e1-seeded-pr-nanocode-openai-20261110T022054Z/watch.txt) |
<!-- evidence:E1:end -->

## E2: implement, test, fix, deliver

`kata run change` on a throwaway repository; a human approves the change
before it is committed. Three cases: `pr`, the change delivered; `refine`,
the same pipeline on a task whose held-out CI gate fails a first attempt
unless the agent acts on the gate's feedback, the live proof of the fix loop;
and `mismatch`, where one byte is written into the execution's workspace while
the run waits for approval.

Every `pr` and `refine` record states two OBSERVED fields, its `variant`
and `refined` lines copied verbatim from the kit's `observed.toml` (that
file's comment lines, such as `iterations`, `final_test`, `refine_cause` and
`iter0_gate_fails`, may come along: they are comments, and nothing requires
them). A `void` record must state `variant` and may leave out `refined`: a run
whose kit stopped before its oracles ran has no `observed.toml`, and the
variant is the task the run was given either way; a `refined` it states is
still checked. The check refuses either field on any other cell or case.

- `variant` is the task text the run was given: `task-only` (the task alone)
  or `refine-addendum` (the task and an addendum telling the agent not to run
  the suite in its own turns) on a `pr` run, `refine-cell` on a `refine` run;
  the check refuses any other pairing. The round's ruling is
  `refine-addendum` on every counted parity run; the check refuses counted
  `pr` runs that differ in variant (see Parity), not a round run wholly on
  `task-only`.
- `refined` is `yes` when the first test iteration (`test#iter-0`) failed and
  a later one ran, else `no`. On a `pr` run it is recorded, never a pass
  condition: a strong model may get the fully specified task right first
  time, and a `pr` pass with `refined = "no"` is valid. The check refuses a
  `refine` pass whose `refined` is not `yes`.

A non-void `pr` or `refine` run's outcome is read from the kit's
`oracles.txt` (`outcome_source = "oracles.txt: ..."`): one `PASS <oracle>`
or `FAIL <oracle>[: <detail>]` line per oracle (only a FAIL line carries a
detail, and no line a carriage return), `kit-intact` last, 10 for `pr` and
18 for `refine`. A run passes exactly when every line is PASS. The check
refuses an oracles.txt with another count, line shape or last oracle, and an
outcome that disagrees with its lines; it does not check which oracles the
other lines name, and a void run, whose oracles may never have run, is not
read. A non-void run of a cell or case no kit writes `oracles.txt` for (E2
`mismatch`, E3, E9) is refused when its `outcome_source` reads one.

`pr` passes when the run completed with the round's task variant; the trunk
tip is the change's commit, its parent is the trunk before the run and its
tree differs from its parent's; the remote branch `kata/<exec>` equals that
commit and exactly one open pull request has it as its head and trunk as its
base; a fresh clone at that commit passes the project's tests; the held-out
oracle passes on it; and no candidate run changed the evidence kit
(`kit-intact`).

`refine` passes when every `pr` condition holds and: the invocation's
held-out gate and test command are the kit's, byte for byte, and neither a
prompt nor a file of the tip holds the gate's source in a form the kit
names; the loop refined; its last iteration passed the whole gate; the gate,
run outside kata on the tip's tree, passes; and a separate scoring set,
which never enters a capsule, passes. A run whose first iteration passes is a `fail`, never re-run to fish
for a refine: the table's `refine` row shows each harness's first non-void
refine run, by `started_utc`, and any later one beside it as not counted.
The refine cell runs in the counted round: the check refuses a round whose
refine runs, of any outcome, are on another `kata_sha` than its parity runs
(see Parity).

The kit writes these artifacts into a `pr` and a `refine` run's directory,
which the check accepts as listed artifacts (it requires only `oracles.txt`
and `kit-sha256.txt`, and only on a non-void run): `oracles.txt`, `observed.toml`, `capsule-path.txt`,
`kit-sha256.txt` (the kit snapshot's manifest), `clone-check.txt`,
`oracle.txt`, `test-iterations.txt`, `refined.txt`, `stages.txt`,
`turns.txt`, `spend.toml`, `pr.json`, `remote-branch.txt`, `tip.txt` and
`clone-path.txt`; and for `refine`, also `refinecheck.txt`,
`gate-unnamed.txt`, `clone-gate.txt`, `oracle-align.txt`,
`change-refine.star` and `params-sha256.txt`. The refine cell's params file
(its `--params-file`, which holds the held-out gate) stays outside the run
directory and is never committed: the check refuses an artifact of any E2
run whose file name, at any depth, is the one the kit gives it
(`<harness>.json`), and cannot see a renamed copy.

`mismatch` passes when the run is refused by name
(`oci_candidate_disk_diverged`) at the commit effect, no branch or pull
request exists for the execution, and trunk is unchanged.

<!-- evidence:E2:begin -->
| Case | codex-stock | nanocode-openai | claude-agent-acp | nanocode-anthropic |
|---|---|---|---|---|
| pr | 3 pass of 3 run(s) | 3 pass of 3 run(s) | 3 pass of 3 run(s) | not yet run |
| mismatch | not yet run | not yet run | not yet run | not yet run |
| refine | pass, refined yes | pass, refined yes | pass, refined yes | not yet run |

| Run | Case | Harness | Surface | kata | Vendor | Model (effort) | Tokens, kata | Tokens, provider | Cost, kata | Cost, provider | Wall | Outcome | Variant | Refined | Read from | Artifacts |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| [e2-pr-claude-agent-acp-20261110T041118Z](runs/e2-pr-claude-agent-acp-20261110T041118Z/run.toml) | pr | claude-agent-acp | cli | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | claude-agent-acp `0.79.0` | claude-sonnet-5-5 (medium) | in 26 / cached 259258 / cache-write 41253 / out 6684 | unavailable: the Anthropic console was not read for the run's window | unavailable | unavailable: the Anthropic console was not read for the run's window | 77 s | **pass** | refine-addendum | yes | oracles.txt: 10 of 10 PASS, kit-intact last | [approvals.txt](runs/e2-pr-claude-agent-acp-20261110T041118Z/approvals.txt), [approve.txt](runs/e2-pr-claude-agent-acp-20261110T041118Z/approve.txt), [capsule-path.txt](runs/e2-pr-claude-agent-acp-20261110T041118Z/capsule-path.txt), [clone-check.txt](runs/e2-pr-claude-agent-acp-20261110T041118Z/clone-check.txt), [clone-path.txt](runs/e2-pr-claude-agent-acp-20261110T041118Z/clone-path.txt), [e2-oracles.log](runs/e2-pr-claude-agent-acp-20261110T041118Z/e2-oracles.log), [ended_utc](runs/e2-pr-claude-agent-acp-20261110T041118Z/ended_utc), [exec](runs/e2-pr-claude-agent-acp-20261110T041118Z/exec), [kit-sha256.txt](runs/e2-pr-claude-agent-acp-20261110T041118Z/kit-sha256.txt), [observed.toml](runs/e2-pr-claude-agent-acp-20261110T041118Z/observed.toml), [oracle.txt](runs/e2-pr-claude-agent-acp-20261110T041118Z/oracle.txt), [oracles.txt](runs/e2-pr-claude-agent-acp-20261110T041118Z/oracles.txt), [pr.json](runs/e2-pr-claude-agent-acp-20261110T041118Z/pr.json), [refined.txt](runs/e2-pr-claude-agent-acp-20261110T041118Z/refined.txt), [remote-branch.txt](runs/e2-pr-claude-agent-acp-20261110T041118Z/remote-branch.txt), [reset.txt](runs/e2-pr-claude-agent-acp-20261110T041118Z/reset.txt), [spend.toml](runs/e2-pr-claude-agent-acp-20261110T041118Z/spend.toml), [stages.txt](runs/e2-pr-claude-agent-acp-20261110T041118Z/stages.txt), [started_utc](runs/e2-pr-claude-agent-acp-20261110T041118Z/started_utc), [submit.json](runs/e2-pr-claude-agent-acp-20261110T041118Z/submit.json), [test-iterations.txt](runs/e2-pr-claude-agent-acp-20261110T041118Z/test-iterations.txt), [tip.txt](runs/e2-pr-claude-agent-acp-20261110T041118Z/tip.txt), [trunk-before.txt](runs/e2-pr-claude-agent-acp-20261110T041118Z/trunk-before.txt), [turns.txt](runs/e2-pr-claude-agent-acp-20261110T041118Z/turns.txt), [wait.json](runs/e2-pr-claude-agent-acp-20261110T041118Z/wait.json), [watch.txt](runs/e2-pr-claude-agent-acp-20261110T041118Z/watch.txt) |
| [e2-pr-claude-agent-acp-20261110T041337Z](runs/e2-pr-claude-agent-acp-20261110T041337Z/run.toml) | pr | claude-agent-acp | cli | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | claude-agent-acp `0.79.0` | claude-sonnet-5-5 (medium) | in 16 / cached 158096 / cache-write 28254 / out 5949 | unavailable: the Anthropic console was not read for the run's window | unavailable | unavailable: the Anthropic console was not read for the run's window | 57 s | **pass** | refine-addendum | no | oracles.txt: 10 of 10 PASS, kit-intact last | [approvals.txt](runs/e2-pr-claude-agent-acp-20261110T041337Z/approvals.txt), [approve.txt](runs/e2-pr-claude-agent-acp-20261110T041337Z/approve.txt), [capsule-path.txt](runs/e2-pr-claude-agent-acp-20261110T041337Z/capsule-path.txt), [clone-check.txt](runs/e2-pr-claude-agent-acp-20261110T041337Z/clone-check.txt), [clone-path.txt](runs/e2-pr-claude-agent-acp-20261110T041337Z/clone-path.txt), [e2-oracles.log](runs/e2-pr-claude-agent-acp-20261110T041337Z/e2-oracles.log), [ended_utc](runs/e2-pr-claude-agent-acp-20261110T041337Z/ended_utc), [exec](runs/e2-pr-claude-agent-acp-20261110T041337Z/exec), [kit-sha256.txt](runs/e2-pr-claude-agent-acp-20261110T041337Z/kit-sha256.txt), [observed.toml](runs/e2-pr-claude-agent-acp-20261110T041337Z/observed.toml), [oracle.txt](runs/e2-pr-claude-agent-acp-20261110T041337Z/oracle.txt), [oracles.txt](runs/e2-pr-claude-agent-acp-20261110T041337Z/oracles.txt), [pr.json](runs/e2-pr-claude-agent-acp-20261110T041337Z/pr.json), [refined.txt](runs/e2-pr-claude-agent-acp-20261110T041337Z/refined.txt), [remote-branch.txt](runs/e2-pr-claude-agent-acp-20261110T041337Z/remote-branch.txt), [reset.txt](runs/e2-pr-claude-agent-acp-20261110T041337Z/reset.txt), [spend.toml](runs/e2-pr-claude-agent-acp-20261110T041337Z/spend.toml), [stages.txt](runs/e2-pr-claude-agent-acp-20261110T041337Z/stages.txt), [started_utc](runs/e2-pr-claude-agent-acp-20261110T041337Z/started_utc), [submit.json](runs/e2-pr-claude-agent-acp-20261110T041337Z/submit.json), [test-iterations.txt](runs/e2-pr-claude-agent-acp-20261110T041337Z/test-iterations.txt), [tip.txt](runs/e2-pr-claude-agent-acp-20261110T041337Z/tip.txt), [trunk-before.txt](runs/e2-pr-claude-agent-acp-20261110T041337Z/trunk-before.txt), [turns.txt](runs/e2-pr-claude-agent-acp-20261110T041337Z/turns.txt), [wait.json](runs/e2-pr-claude-agent-acp-20261110T041337Z/wait.json), [watch.txt](runs/e2-pr-claude-agent-acp-20261110T041337Z/watch.txt) |
| [e2-pr-claude-agent-acp-20261110T041520Z](runs/e2-pr-claude-agent-acp-20261110T041520Z/run.toml) | pr | claude-agent-acp | cli | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | claude-agent-acp `0.79.0` | claude-sonnet-5-5 (medium) | in 14 / cached 130032 / cache-write 27088 / out 4928 | unavailable: the Anthropic console was not read for the run's window | unavailable | unavailable: the Anthropic console was not read for the run's window | 52 s | **pass** | refine-addendum | no | oracles.txt: 10 of 10 PASS, kit-intact last | [approvals.txt](runs/e2-pr-claude-agent-acp-20261110T041520Z/approvals.txt), [approve.txt](runs/e2-pr-claude-agent-acp-20261110T041520Z/approve.txt), [capsule-path.txt](runs/e2-pr-claude-agent-acp-20261110T041520Z/capsule-path.txt), [clone-check.txt](runs/e2-pr-claude-agent-acp-20261110T041520Z/clone-check.txt), [clone-path.txt](runs/e2-pr-claude-agent-acp-20261110T041520Z/clone-path.txt), [e2-oracles.log](runs/e2-pr-claude-agent-acp-20261110T041520Z/e2-oracles.log), [ended_utc](runs/e2-pr-claude-agent-acp-20261110T041520Z/ended_utc), [exec](runs/e2-pr-claude-agent-acp-20261110T041520Z/exec), [kit-sha256.txt](runs/e2-pr-claude-agent-acp-20261110T041520Z/kit-sha256.txt), [observed.toml](runs/e2-pr-claude-agent-acp-20261110T041520Z/observed.toml), [oracle.txt](runs/e2-pr-claude-agent-acp-20261110T041520Z/oracle.txt), [oracles.txt](runs/e2-pr-claude-agent-acp-20261110T041520Z/oracles.txt), [pr.json](runs/e2-pr-claude-agent-acp-20261110T041520Z/pr.json), [refined.txt](runs/e2-pr-claude-agent-acp-20261110T041520Z/refined.txt), [remote-branch.txt](runs/e2-pr-claude-agent-acp-20261110T041520Z/remote-branch.txt), [reset.txt](runs/e2-pr-claude-agent-acp-20261110T041520Z/reset.txt), [spend.toml](runs/e2-pr-claude-agent-acp-20261110T041520Z/spend.toml), [stages.txt](runs/e2-pr-claude-agent-acp-20261110T041520Z/stages.txt), [started_utc](runs/e2-pr-claude-agent-acp-20261110T041520Z/started_utc), [submit.json](runs/e2-pr-claude-agent-acp-20261110T041520Z/submit.json), [test-iterations.txt](runs/e2-pr-claude-agent-acp-20261110T041520Z/test-iterations.txt), [tip.txt](runs/e2-pr-claude-agent-acp-20261110T041520Z/tip.txt), [trunk-before.txt](runs/e2-pr-claude-agent-acp-20261110T041520Z/trunk-before.txt), [turns.txt](runs/e2-pr-claude-agent-acp-20261110T041520Z/turns.txt), [wait.json](runs/e2-pr-claude-agent-acp-20261110T041520Z/wait.json), [watch.txt](runs/e2-pr-claude-agent-acp-20261110T041520Z/watch.txt) |
| [e2-pr-codex-stock-20261110T033859Z](runs/e2-pr-codex-stock-20261110T033859Z/run.toml) | pr | codex-stock | cli | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | codex `codex-cli 0.165.0` | gpt-6-luna (medium) | in 78311 / cached 282240 / cache-write 0 / out 5220 | unavailable: a subscription login has no per-token view | unavailable | unavailable: subscription | 128 s | **pass** | refine-addendum | yes | oracles.txt: 10 of 10 PASS, kit-intact last | [approvals.txt](runs/e2-pr-codex-stock-20261110T033859Z/approvals.txt), [approve.txt](runs/e2-pr-codex-stock-20261110T033859Z/approve.txt), [capsule-path.txt](runs/e2-pr-codex-stock-20261110T033859Z/capsule-path.txt), [clone-check.txt](runs/e2-pr-codex-stock-20261110T033859Z/clone-check.txt), [clone-path.txt](runs/e2-pr-codex-stock-20261110T033859Z/clone-path.txt), [e2-oracles.log](runs/e2-pr-codex-stock-20261110T033859Z/e2-oracles.log), [ended_utc](runs/e2-pr-codex-stock-20261110T033859Z/ended_utc), [exec](runs/e2-pr-codex-stock-20261110T033859Z/exec), [kit-sha256.txt](runs/e2-pr-codex-stock-20261110T033859Z/kit-sha256.txt), [observed.toml](runs/e2-pr-codex-stock-20261110T033859Z/observed.toml), [oracle.txt](runs/e2-pr-codex-stock-20261110T033859Z/oracle.txt), [oracles.txt](runs/e2-pr-codex-stock-20261110T033859Z/oracles.txt), [pr.json](runs/e2-pr-codex-stock-20261110T033859Z/pr.json), [refined.txt](runs/e2-pr-codex-stock-20261110T033859Z/refined.txt), [remote-branch.txt](runs/e2-pr-codex-stock-20261110T033859Z/remote-branch.txt), [reset.txt](runs/e2-pr-codex-stock-20261110T033859Z/reset.txt), [spend.toml](runs/e2-pr-codex-stock-20261110T033859Z/spend.toml), [stages.txt](runs/e2-pr-codex-stock-20261110T033859Z/stages.txt), [started_utc](runs/e2-pr-codex-stock-20261110T033859Z/started_utc), [submit.json](runs/e2-pr-codex-stock-20261110T033859Z/submit.json), [test-iterations.txt](runs/e2-pr-codex-stock-20261110T033859Z/test-iterations.txt), [tip.txt](runs/e2-pr-codex-stock-20261110T033859Z/tip.txt), [trunk-before.txt](runs/e2-pr-codex-stock-20261110T033859Z/trunk-before.txt), [turns.txt](runs/e2-pr-codex-stock-20261110T033859Z/turns.txt), [wait.json](runs/e2-pr-codex-stock-20261110T033859Z/wait.json), [watch.txt](runs/e2-pr-codex-stock-20261110T033859Z/watch.txt) |
| [e2-pr-codex-stock-20261110T034210Z](runs/e2-pr-codex-stock-20261110T034210Z/run.toml) | pr | codex-stock | cli | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | codex `codex-cli 0.165.0` | gpt-6-luna (medium) | in 63391 / cached 176768 / cache-write 0 / out 4874 | unavailable: a subscription login has no per-token view | unavailable | unavailable: subscription | 113 s | **pass** | refine-addendum | no | oracles.txt: 10 of 10 PASS, kit-intact last | [approvals.txt](runs/e2-pr-codex-stock-20261110T034210Z/approvals.txt), [approve.txt](runs/e2-pr-codex-stock-20261110T034210Z/approve.txt), [capsule-path.txt](runs/e2-pr-codex-stock-20261110T034210Z/capsule-path.txt), [clone-check.txt](runs/e2-pr-codex-stock-20261110T034210Z/clone-check.txt), [clone-path.txt](runs/e2-pr-codex-stock-20261110T034210Z/clone-path.txt), [e2-oracles.log](runs/e2-pr-codex-stock-20261110T034210Z/e2-oracles.log), [ended_utc](runs/e2-pr-codex-stock-20261110T034210Z/ended_utc), [exec](runs/e2-pr-codex-stock-20261110T034210Z/exec), [kit-sha256.txt](runs/e2-pr-codex-stock-20261110T034210Z/kit-sha256.txt), [observed.toml](runs/e2-pr-codex-stock-20261110T034210Z/observed.toml), [oracle.txt](runs/e2-pr-codex-stock-20261110T034210Z/oracle.txt), [oracles.txt](runs/e2-pr-codex-stock-20261110T034210Z/oracles.txt), [pr.json](runs/e2-pr-codex-stock-20261110T034210Z/pr.json), [refined.txt](runs/e2-pr-codex-stock-20261110T034210Z/refined.txt), [remote-branch.txt](runs/e2-pr-codex-stock-20261110T034210Z/remote-branch.txt), [reset.txt](runs/e2-pr-codex-stock-20261110T034210Z/reset.txt), [spend.toml](runs/e2-pr-codex-stock-20261110T034210Z/spend.toml), [stages.txt](runs/e2-pr-codex-stock-20261110T034210Z/stages.txt), [started_utc](runs/e2-pr-codex-stock-20261110T034210Z/started_utc), [submit.json](runs/e2-pr-codex-stock-20261110T034210Z/submit.json), [test-iterations.txt](runs/e2-pr-codex-stock-20261110T034210Z/test-iterations.txt), [tip.txt](runs/e2-pr-codex-stock-20261110T034210Z/tip.txt), [trunk-before.txt](runs/e2-pr-codex-stock-20261110T034210Z/trunk-before.txt), [turns.txt](runs/e2-pr-codex-stock-20261110T034210Z/turns.txt), [wait.json](runs/e2-pr-codex-stock-20261110T034210Z/wait.json), [watch.txt](runs/e2-pr-codex-stock-20261110T034210Z/watch.txt) |
| [e2-pr-codex-stock-20261110T034844Z](runs/e2-pr-codex-stock-20261110T034844Z/run.toml) | pr | codex-stock | cli | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | codex `codex-cli 0.165.0` | gpt-6-luna (medium) | in 36208 / cached 154752 / cache-write 0 / out 3543 | unavailable: a subscription login has no per-token view | unavailable | unavailable: subscription | 89 s | **pass** | refine-addendum | no | oracles.txt: 10 of 10 PASS, kit-intact last | [approvals.txt](runs/e2-pr-codex-stock-20261110T034844Z/approvals.txt), [approve.txt](runs/e2-pr-codex-stock-20261110T034844Z/approve.txt), [capsule-path.txt](runs/e2-pr-codex-stock-20261110T034844Z/capsule-path.txt), [clone-check.txt](runs/e2-pr-codex-stock-20261110T034844Z/clone-check.txt), [clone-path.txt](runs/e2-pr-codex-stock-20261110T034844Z/clone-path.txt), [e2-oracles.log](runs/e2-pr-codex-stock-20261110T034844Z/e2-oracles.log), [ended_utc](runs/e2-pr-codex-stock-20261110T034844Z/ended_utc), [exec](runs/e2-pr-codex-stock-20261110T034844Z/exec), [kit-sha256.txt](runs/e2-pr-codex-stock-20261110T034844Z/kit-sha256.txt), [observed.toml](runs/e2-pr-codex-stock-20261110T034844Z/observed.toml), [oracle.txt](runs/e2-pr-codex-stock-20261110T034844Z/oracle.txt), [oracles.txt](runs/e2-pr-codex-stock-20261110T034844Z/oracles.txt), [pr.json](runs/e2-pr-codex-stock-20261110T034844Z/pr.json), [refined.txt](runs/e2-pr-codex-stock-20261110T034844Z/refined.txt), [remote-branch.txt](runs/e2-pr-codex-stock-20261110T034844Z/remote-branch.txt), [reset.txt](runs/e2-pr-codex-stock-20261110T034844Z/reset.txt), [spend.toml](runs/e2-pr-codex-stock-20261110T034844Z/spend.toml), [stages.txt](runs/e2-pr-codex-stock-20261110T034844Z/stages.txt), [started_utc](runs/e2-pr-codex-stock-20261110T034844Z/started_utc), [submit.json](runs/e2-pr-codex-stock-20261110T034844Z/submit.json), [test-iterations.txt](runs/e2-pr-codex-stock-20261110T034844Z/test-iterations.txt), [tip.txt](runs/e2-pr-codex-stock-20261110T034844Z/tip.txt), [trunk-before.txt](runs/e2-pr-codex-stock-20261110T034844Z/trunk-before.txt), [turns.txt](runs/e2-pr-codex-stock-20261110T034844Z/turns.txt), [wait.json](runs/e2-pr-codex-stock-20261110T034844Z/wait.json), [watch.txt](runs/e2-pr-codex-stock-20261110T034844Z/watch.txt) |
| [e2-pr-nanocode-openai-20261110T022639Z](runs/e2-pr-nanocode-openai-20261110T022639Z/run.toml) | pr | nanocode-openai | cli | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | nanocode `2ac77424e032` | gpt-6-luna (medium) | in 62445 / cached 82048 / cache-write 0 / out 4244 | unavailable: a subscription login has no per-token view | unavailable | unavailable: subscription | 109 s | **pass** | refine-addendum | yes | oracles.txt: 10 of 10 PASS, kit-intact last | [approvals.txt](runs/e2-pr-nanocode-openai-20261110T022639Z/approvals.txt), [approve.txt](runs/e2-pr-nanocode-openai-20261110T022639Z/approve.txt), [capsule-path.txt](runs/e2-pr-nanocode-openai-20261110T022639Z/capsule-path.txt), [clone-check.txt](runs/e2-pr-nanocode-openai-20261110T022639Z/clone-check.txt), [clone-path.txt](runs/e2-pr-nanocode-openai-20261110T022639Z/clone-path.txt), [e2-oracles.log](runs/e2-pr-nanocode-openai-20261110T022639Z/e2-oracles.log), [ended_utc](runs/e2-pr-nanocode-openai-20261110T022639Z/ended_utc), [exec](runs/e2-pr-nanocode-openai-20261110T022639Z/exec), [kit-sha256.txt](runs/e2-pr-nanocode-openai-20261110T022639Z/kit-sha256.txt), [observed.toml](runs/e2-pr-nanocode-openai-20261110T022639Z/observed.toml), [oracle.txt](runs/e2-pr-nanocode-openai-20261110T022639Z/oracle.txt), [oracles.txt](runs/e2-pr-nanocode-openai-20261110T022639Z/oracles.txt), [pr.json](runs/e2-pr-nanocode-openai-20261110T022639Z/pr.json), [refined.txt](runs/e2-pr-nanocode-openai-20261110T022639Z/refined.txt), [remote-branch.txt](runs/e2-pr-nanocode-openai-20261110T022639Z/remote-branch.txt), [reset.txt](runs/e2-pr-nanocode-openai-20261110T022639Z/reset.txt), [spend.toml](runs/e2-pr-nanocode-openai-20261110T022639Z/spend.toml), [stages.txt](runs/e2-pr-nanocode-openai-20261110T022639Z/stages.txt), [started_utc](runs/e2-pr-nanocode-openai-20261110T022639Z/started_utc), [submit.json](runs/e2-pr-nanocode-openai-20261110T022639Z/submit.json), [test-iterations.txt](runs/e2-pr-nanocode-openai-20261110T022639Z/test-iterations.txt), [tip.txt](runs/e2-pr-nanocode-openai-20261110T022639Z/tip.txt), [trunk-before.txt](runs/e2-pr-nanocode-openai-20261110T022639Z/trunk-before.txt), [turns.txt](runs/e2-pr-nanocode-openai-20261110T022639Z/turns.txt), [wait.json](runs/e2-pr-nanocode-openai-20261110T022639Z/wait.json), [watch.txt](runs/e2-pr-nanocode-openai-20261110T022639Z/watch.txt) |
| [e2-pr-nanocode-openai-20261110T022932Z](runs/e2-pr-nanocode-openai-20261110T022932Z/run.toml) | pr | nanocode-openai | cli | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | nanocode `2ac77424e032` | gpt-6-luna (medium) | in 39334 / cached 106624 / cache-write 0 / out 4349 | unavailable: a subscription login has no per-token view | unavailable | unavailable: subscription | 103 s | **pass** | refine-addendum | no | oracles.txt: 10 of 10 PASS, kit-intact last | [approvals.txt](runs/e2-pr-nanocode-openai-20261110T022932Z/approvals.txt), [approve.txt](runs/e2-pr-nanocode-openai-20261110T022932Z/approve.txt), [capsule-path.txt](runs/e2-pr-nanocode-openai-20261110T022932Z/capsule-path.txt), [clone-check.txt](runs/e2-pr-nanocode-openai-20261110T022932Z/clone-check.txt), [clone-path.txt](runs/e2-pr-nanocode-openai-20261110T022932Z/clone-path.txt), [e2-oracles.log](runs/e2-pr-nanocode-openai-20261110T022932Z/e2-oracles.log), [ended_utc](runs/e2-pr-nanocode-openai-20261110T022932Z/ended_utc), [exec](runs/e2-pr-nanocode-openai-20261110T022932Z/exec), [kit-sha256.txt](runs/e2-pr-nanocode-openai-20261110T022932Z/kit-sha256.txt), [observed.toml](runs/e2-pr-nanocode-openai-20261110T022932Z/observed.toml), [oracle.txt](runs/e2-pr-nanocode-openai-20261110T022932Z/oracle.txt), [oracles.txt](runs/e2-pr-nanocode-openai-20261110T022932Z/oracles.txt), [pr.json](runs/e2-pr-nanocode-openai-20261110T022932Z/pr.json), [refined.txt](runs/e2-pr-nanocode-openai-20261110T022932Z/refined.txt), [remote-branch.txt](runs/e2-pr-nanocode-openai-20261110T022932Z/remote-branch.txt), [reset.txt](runs/e2-pr-nanocode-openai-20261110T022932Z/reset.txt), [spend.toml](runs/e2-pr-nanocode-openai-20261110T022932Z/spend.toml), [stages.txt](runs/e2-pr-nanocode-openai-20261110T022932Z/stages.txt), [started_utc](runs/e2-pr-nanocode-openai-20261110T022932Z/started_utc), [submit.json](runs/e2-pr-nanocode-openai-20261110T022932Z/submit.json), [test-iterations.txt](runs/e2-pr-nanocode-openai-20261110T022932Z/test-iterations.txt), [tip.txt](runs/e2-pr-nanocode-openai-20261110T022932Z/tip.txt), [trunk-before.txt](runs/e2-pr-nanocode-openai-20261110T022932Z/trunk-before.txt), [turns.txt](runs/e2-pr-nanocode-openai-20261110T022932Z/turns.txt), [wait.json](runs/e2-pr-nanocode-openai-20261110T022932Z/wait.json), [watch.txt](runs/e2-pr-nanocode-openai-20261110T022932Z/watch.txt) |
| [e2-pr-nanocode-openai-20261110T024855Z](runs/e2-pr-nanocode-openai-20261110T024855Z/run.toml) | pr | nanocode-openai | cli | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | nanocode `2ac77424e032` | gpt-6-luna (medium) | in 61921 / cached 130048 / cache-write 0 / out 5156 | unavailable: a subscription login has no per-token view | unavailable | unavailable: subscription | 134 s | **pass** | refine-addendum | no | oracles.txt: 10 of 10 PASS, kit-intact last | [approvals.txt](runs/e2-pr-nanocode-openai-20261110T024855Z/approvals.txt), [approve.txt](runs/e2-pr-nanocode-openai-20261110T024855Z/approve.txt), [capsule-path.txt](runs/e2-pr-nanocode-openai-20261110T024855Z/capsule-path.txt), [clone-check.txt](runs/e2-pr-nanocode-openai-20261110T024855Z/clone-check.txt), [clone-path.txt](runs/e2-pr-nanocode-openai-20261110T024855Z/clone-path.txt), [e2-oracles.log](runs/e2-pr-nanocode-openai-20261110T024855Z/e2-oracles.log), [ended_utc](runs/e2-pr-nanocode-openai-20261110T024855Z/ended_utc), [exec](runs/e2-pr-nanocode-openai-20261110T024855Z/exec), [kit-sha256.txt](runs/e2-pr-nanocode-openai-20261110T024855Z/kit-sha256.txt), [observed.toml](runs/e2-pr-nanocode-openai-20261110T024855Z/observed.toml), [oracle.txt](runs/e2-pr-nanocode-openai-20261110T024855Z/oracle.txt), [oracles.txt](runs/e2-pr-nanocode-openai-20261110T024855Z/oracles.txt), [pr.json](runs/e2-pr-nanocode-openai-20261110T024855Z/pr.json), [refined.txt](runs/e2-pr-nanocode-openai-20261110T024855Z/refined.txt), [remote-branch.txt](runs/e2-pr-nanocode-openai-20261110T024855Z/remote-branch.txt), [reset.txt](runs/e2-pr-nanocode-openai-20261110T024855Z/reset.txt), [spend.toml](runs/e2-pr-nanocode-openai-20261110T024855Z/spend.toml), [stages.txt](runs/e2-pr-nanocode-openai-20261110T024855Z/stages.txt), [started_utc](runs/e2-pr-nanocode-openai-20261110T024855Z/started_utc), [submit.json](runs/e2-pr-nanocode-openai-20261110T024855Z/submit.json), [test-iterations.txt](runs/e2-pr-nanocode-openai-20261110T024855Z/test-iterations.txt), [tip.txt](runs/e2-pr-nanocode-openai-20261110T024855Z/tip.txt), [trunk-before.txt](runs/e2-pr-nanocode-openai-20261110T024855Z/trunk-before.txt), [turns.txt](runs/e2-pr-nanocode-openai-20261110T024855Z/turns.txt), [wait.json](runs/e2-pr-nanocode-openai-20261110T024855Z/wait.json), [watch.txt](runs/e2-pr-nanocode-openai-20261110T024855Z/watch.txt) |
| [e2-refine-claude-agent-acp-20261110T041652Z](runs/e2-refine-claude-agent-acp-20261110T041652Z/run.toml) | refine | claude-agent-acp | cli | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | claude-agent-acp `0.79.0` | claude-sonnet-5-5 (medium) | in 24 / cached 265958 / cache-write 52614 / out 10469 | unavailable: the Anthropic console was not read for the run's window | unavailable | unavailable: the Anthropic console was not read for the run's window | 98 s | **pass** | refine-cell | yes | oracles.txt: 18 of 18 PASS, kit-intact last | [approvals.txt](runs/e2-refine-claude-agent-acp-20261110T041652Z/approvals.txt), [approve.txt](runs/e2-refine-claude-agent-acp-20261110T041652Z/approve.txt), [capsule-path.txt](runs/e2-refine-claude-agent-acp-20261110T041652Z/capsule-path.txt), [change-refine.star](runs/e2-refine-claude-agent-acp-20261110T041652Z/change-refine.star), [check-refine.txt](runs/e2-refine-claude-agent-acp-20261110T041652Z/check-refine.txt), [clone-check.txt](runs/e2-refine-claude-agent-acp-20261110T041652Z/clone-check.txt), [clone-gate.txt](runs/e2-refine-claude-agent-acp-20261110T041652Z/clone-gate.txt), [clone-path.txt](runs/e2-refine-claude-agent-acp-20261110T041652Z/clone-path.txt), [e2-oracles.log](runs/e2-refine-claude-agent-acp-20261110T041652Z/e2-oracles.log), [ended_utc](runs/e2-refine-claude-agent-acp-20261110T041652Z/ended_utc), [exec](runs/e2-refine-claude-agent-acp-20261110T041652Z/exec), [gate-unnamed.txt](runs/e2-refine-claude-agent-acp-20261110T041652Z/gate-unnamed.txt), [kit-sha256.txt](runs/e2-refine-claude-agent-acp-20261110T041652Z/kit-sha256.txt), [observed.toml](runs/e2-refine-claude-agent-acp-20261110T041652Z/observed.toml), [oracle-align.txt](runs/e2-refine-claude-agent-acp-20261110T041652Z/oracle-align.txt), [oracle.txt](runs/e2-refine-claude-agent-acp-20261110T041652Z/oracle.txt), [oracles.txt](runs/e2-refine-claude-agent-acp-20261110T041652Z/oracles.txt), [params-sha256.txt](runs/e2-refine-claude-agent-acp-20261110T041652Z/params-sha256.txt), [pr.json](runs/e2-refine-claude-agent-acp-20261110T041652Z/pr.json), [refine-pack.txt](runs/e2-refine-claude-agent-acp-20261110T041652Z/refine-pack.txt), [refinecheck.txt](runs/e2-refine-claude-agent-acp-20261110T041652Z/refinecheck.txt), [refined.txt](runs/e2-refine-claude-agent-acp-20261110T041652Z/refined.txt), [remote-branch.txt](runs/e2-refine-claude-agent-acp-20261110T041652Z/remote-branch.txt), [reset.txt](runs/e2-refine-claude-agent-acp-20261110T041652Z/reset.txt), [spend.toml](runs/e2-refine-claude-agent-acp-20261110T041652Z/spend.toml), [stages.txt](runs/e2-refine-claude-agent-acp-20261110T041652Z/stages.txt), [started_utc](runs/e2-refine-claude-agent-acp-20261110T041652Z/started_utc), [submit.json](runs/e2-refine-claude-agent-acp-20261110T041652Z/submit.json), [test-iterations.txt](runs/e2-refine-claude-agent-acp-20261110T041652Z/test-iterations.txt), [tip.txt](runs/e2-refine-claude-agent-acp-20261110T041652Z/tip.txt), [trunk-before.txt](runs/e2-refine-claude-agent-acp-20261110T041652Z/trunk-before.txt), [turns.txt](runs/e2-refine-claude-agent-acp-20261110T041652Z/turns.txt), [wait.json](runs/e2-refine-claude-agent-acp-20261110T041652Z/wait.json), [watch.txt](runs/e2-refine-claude-agent-acp-20261110T041652Z/watch.txt) |
| [e2-refine-codex-stock-20261110T035444Z](runs/e2-refine-codex-stock-20261110T035444Z/run.toml) | refine | codex-stock | cli | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | codex `codex-cli 0.165.0` | gpt-6-luna (medium) | in 76290 / cached 401408 / cache-write 0 / out 6487 | unavailable: a subscription login has no per-token view | unavailable | unavailable: subscription | 148 s | **pass** | refine-cell | yes | oracles.txt: 18 of 18 PASS, kit-intact last | [approvals.txt](runs/e2-refine-codex-stock-20261110T035444Z/approvals.txt), [approve.txt](runs/e2-refine-codex-stock-20261110T035444Z/approve.txt), [capsule-path.txt](runs/e2-refine-codex-stock-20261110T035444Z/capsule-path.txt), [change-refine.star](runs/e2-refine-codex-stock-20261110T035444Z/change-refine.star), [check-refine.txt](runs/e2-refine-codex-stock-20261110T035444Z/check-refine.txt), [clone-check.txt](runs/e2-refine-codex-stock-20261110T035444Z/clone-check.txt), [clone-gate.txt](runs/e2-refine-codex-stock-20261110T035444Z/clone-gate.txt), [clone-path.txt](runs/e2-refine-codex-stock-20261110T035444Z/clone-path.txt), [e2-oracles.log](runs/e2-refine-codex-stock-20261110T035444Z/e2-oracles.log), [ended_utc](runs/e2-refine-codex-stock-20261110T035444Z/ended_utc), [exec](runs/e2-refine-codex-stock-20261110T035444Z/exec), [gate-unnamed.txt](runs/e2-refine-codex-stock-20261110T035444Z/gate-unnamed.txt), [kit-sha256.txt](runs/e2-refine-codex-stock-20261110T035444Z/kit-sha256.txt), [observed.toml](runs/e2-refine-codex-stock-20261110T035444Z/observed.toml), [oracle-align.txt](runs/e2-refine-codex-stock-20261110T035444Z/oracle-align.txt), [oracle.txt](runs/e2-refine-codex-stock-20261110T035444Z/oracle.txt), [oracles.txt](runs/e2-refine-codex-stock-20261110T035444Z/oracles.txt), [params-sha256.txt](runs/e2-refine-codex-stock-20261110T035444Z/params-sha256.txt), [pr.json](runs/e2-refine-codex-stock-20261110T035444Z/pr.json), [refine-pack.txt](runs/e2-refine-codex-stock-20261110T035444Z/refine-pack.txt), [refinecheck.txt](runs/e2-refine-codex-stock-20261110T035444Z/refinecheck.txt), [refined.txt](runs/e2-refine-codex-stock-20261110T035444Z/refined.txt), [remote-branch.txt](runs/e2-refine-codex-stock-20261110T035444Z/remote-branch.txt), [reset.txt](runs/e2-refine-codex-stock-20261110T035444Z/reset.txt), [spend.toml](runs/e2-refine-codex-stock-20261110T035444Z/spend.toml), [stages.txt](runs/e2-refine-codex-stock-20261110T035444Z/stages.txt), [started_utc](runs/e2-refine-codex-stock-20261110T035444Z/started_utc), [submit.json](runs/e2-refine-codex-stock-20261110T035444Z/submit.json), [test-iterations.txt](runs/e2-refine-codex-stock-20261110T035444Z/test-iterations.txt), [tip.txt](runs/e2-refine-codex-stock-20261110T035444Z/tip.txt), [trunk-before.txt](runs/e2-refine-codex-stock-20261110T035444Z/trunk-before.txt), [turns.txt](runs/e2-refine-codex-stock-20261110T035444Z/turns.txt), [wait.json](runs/e2-refine-codex-stock-20261110T035444Z/wait.json), [watch.txt](runs/e2-refine-codex-stock-20261110T035444Z/watch.txt) |
| [e2-refine-nanocode-openai-20261110T025759Z](runs/e2-refine-nanocode-openai-20261110T025759Z/run.toml) | refine | nanocode-openai | cli | `34d5c77c8ff7` (tree `7e2bfed23cf5`) | nanocode `2ac77424e032` | gpt-6-luna (medium) | in 112899 / cached 156160 / cache-write 0 / out 5625 | unavailable: a subscription login has no per-token view | unavailable | unavailable: subscription | 166 s | **pass** | refine-cell | yes | oracles.txt: 18 of 18 PASS, kit-intact last | [approvals.txt](runs/e2-refine-nanocode-openai-20261110T025759Z/approvals.txt), [approve.txt](runs/e2-refine-nanocode-openai-20261110T025759Z/approve.txt), [capsule-path.txt](runs/e2-refine-nanocode-openai-20261110T025759Z/capsule-path.txt), [change-refine.star](runs/e2-refine-nanocode-openai-20261110T025759Z/change-refine.star), [check-refine.txt](runs/e2-refine-nanocode-openai-20261110T025759Z/check-refine.txt), [clone-check.txt](runs/e2-refine-nanocode-openai-20261110T025759Z/clone-check.txt), [clone-gate.txt](runs/e2-refine-nanocode-openai-20261110T025759Z/clone-gate.txt), [clone-path.txt](runs/e2-refine-nanocode-openai-20261110T025759Z/clone-path.txt), [e2-oracles.log](runs/e2-refine-nanocode-openai-20261110T025759Z/e2-oracles.log), [ended_utc](runs/e2-refine-nanocode-openai-20261110T025759Z/ended_utc), [exec](runs/e2-refine-nanocode-openai-20261110T025759Z/exec), [gate-unnamed.txt](runs/e2-refine-nanocode-openai-20261110T025759Z/gate-unnamed.txt), [kit-sha256.txt](runs/e2-refine-nanocode-openai-20261110T025759Z/kit-sha256.txt), [observed.toml](runs/e2-refine-nanocode-openai-20261110T025759Z/observed.toml), [oracle-align.txt](runs/e2-refine-nanocode-openai-20261110T025759Z/oracle-align.txt), [oracle.txt](runs/e2-refine-nanocode-openai-20261110T025759Z/oracle.txt), [oracles.txt](runs/e2-refine-nanocode-openai-20261110T025759Z/oracles.txt), [params-sha256.txt](runs/e2-refine-nanocode-openai-20261110T025759Z/params-sha256.txt), [pr.json](runs/e2-refine-nanocode-openai-20261110T025759Z/pr.json), [refine-pack.txt](runs/e2-refine-nanocode-openai-20261110T025759Z/refine-pack.txt), [refinecheck.txt](runs/e2-refine-nanocode-openai-20261110T025759Z/refinecheck.txt), [refined.txt](runs/e2-refine-nanocode-openai-20261110T025759Z/refined.txt), [remote-branch.txt](runs/e2-refine-nanocode-openai-20261110T025759Z/remote-branch.txt), [reset.txt](runs/e2-refine-nanocode-openai-20261110T025759Z/reset.txt), [spend.toml](runs/e2-refine-nanocode-openai-20261110T025759Z/spend.toml), [stages.txt](runs/e2-refine-nanocode-openai-20261110T025759Z/stages.txt), [started_utc](runs/e2-refine-nanocode-openai-20261110T025759Z/started_utc), [submit.json](runs/e2-refine-nanocode-openai-20261110T025759Z/submit.json), [test-iterations.txt](runs/e2-refine-nanocode-openai-20261110T025759Z/test-iterations.txt), [tip.txt](runs/e2-refine-nanocode-openai-20261110T025759Z/tip.txt), [trunk-before.txt](runs/e2-refine-nanocode-openai-20261110T025759Z/trunk-before.txt), [turns.txt](runs/e2-refine-nanocode-openai-20261110T025759Z/turns.txt), [wait.json](runs/e2-refine-nanocode-openai-20261110T025759Z/wait.json), [watch.txt](runs/e2-refine-nanocode-openai-20261110T025759Z/watch.txt) |
<!-- evidence:E2:end -->

## E3: crash and restart

The change workflow on the throwaway repository, killed at fixed points, on
an installed main with an external worker; after any main kill the worker is
restarted too. The matrix runs on `nanocode-openai` and, as its anthropic
arm, on `nanocode-anthropic`, each on its pair's model and effort; each arm
has its own column below.

| Case | Kill | Expected settlement |
|---|---|---|
| `gate-main-kill`, `gate-worker-kill` | the main, or the worker, while the run waits at its approval gate | the run resumes at the gate; no model call is in flight |
| `P1` | the main, after the capsule is placed and before it is sent | PROVEN AMBIGUOUS at restart, never re-delivered; zero model calls for that attempt |
| `P2` | the worker, while a model call is in flight (read from the client-side transcript of kata's own progress frames; the kernel's socket table at the kill is recorded beside it, not judged) | PROVEN AMBIGUOUS; no second attempt; no workspace change published; no container or cgroup left |
| `P3` | the worker, after the turn's container exited and before its result left the worker | PROVEN AMBIGUOUS, settled when the main sees the worker die, never re-delivered; one attempt, claimed once; the run fails and its candidate is parked |
| `P4` | the main, between the push and the pull request | at restart, one pull request opened; exactly one `kata/<exec>` branch, equal to the delivered commit |
| `P1-host` … `P4-host` | the virtual machine, at the same points, with every node process frozen first | the same settlements after the machine restarts on the same disk |

A fault-injected case counts only when its positive controls hold: the
injected point is a registered crash boundary, the killed process printed the
point-reached marker, and it died by the expected signal (a host case: the
process was stopped at the point, then the whole node was frozen and still
stood at the point: `P1-host` and `P3-host` with the attempt unsettled, read
outside kata from the raw database (a read that fails is no control);
`P2-host` with the call still open, read from kata's own progress frames in the
client-side transcript (the kernel's sockets recorded beside it, not judged);
`P4-host` with exactly one acknowledged `kata/<exec>` and no pull request, read
from the forge). Otherwise the
run is `void`, its `void_reason` names the control that did not hold, and
void counts are shown. Every E3 record states the
settlement it observed (`settlement`), and its row shows it beside the
expected one, including one that differs; a run passes only with the
expected settlement. A finished turn whose result never reached the main is
not accepted later: the main accepts a capsule's result in the one
transaction that receives it, and capsule re-delivery is not implemented, so
`P3` settles PROVEN AMBIGUOUS. Spend is accounted
as the completed attempts' recorded usage, the number of issued calls whose usage
is unknown (`unmetered_calls`: every call, completed or not, of an attempt that
never completed, since its usage is on no durable row; the rig counts it in every
case, and `P1`, the gate cases and `P4`, which kill no model call, require 0), the number of attempts kata could not meter
(`unknown_charges`, read through `ledger.py`), and no re-run of the same stage.

The machine of the host cases is the E9 virtual machine. `scripts/e9-vm.sh
kill-host` sends SIGKILL to its qemu, and `start` boots the same disk again;
`e3-host <case> <out>` drives one host case across that kill (its header states
each step) and copies the cell's records and kept data out on every exit path.
The cell flushes the machine's disks once, before the run is submitted: that
flush covers the rig's setup AND the booted node's own state (its database and
files as they stood at boot), so the host column tests what the RUN left
unflushed, not kata's boot-time durability. Its disk mode is fixed at
`cache=none,aio=native`, with no setting to change it: guest writes bypass the
host page cache, what the guest had flushed survives the kill and what it had
not is lost. That models a power loss of the guest, not of the host.
The host cases' forge is the rig's local bare repository and fake `gh` on the
same machine, made to keep what it acknowledged as a forge on another machine
does: the bare fsyncs every object and ref it receives (`core.fsync=all`, and
a hook that fsyncs each committed ref and its directory before the push is
acknowledged; measured: without the hook git renames the ref after its last
fsync), and the fake `gh` fsyncs its log on every call. Before the restarted
main boots, `P4-host` reads that forge (its `kata/<exec>` and `git fsck`) and
is void unless it holds exactly what was acknowledged before the kill. The
forge still shares the guest's file system, so its fsync also commits that
file system's journal transaction: kata's pending metadata and, under ext4's
default `data=ordered`, the data of kata's files whose blocks that commit
allocates (a file replaced by rename among them). A `P4-host` pass therefore
does not show that kata made its own writes between the submit and the push
durable.

The 0.0.1 round ran E3: the process column once per case on
each arm, `P4` against the real fixture forge (`N0xMare/kata-e2-fixture`, read
with `git ls-remote` and `gh`), and the host column on `nanocode-anthropic` only;
its `nanocode-openai` cells were not run. No record is void. `P2-host` is a
`fail` from a defect in the test rig, not in kata's settlement: kata settled the
attempt PROVEN AMBIGUOUS, with the reason (kata's own words; the rig checked no
re-delivery) "the main
restarted. PROVEN AMBIGUOUS: …", the settlement a whole-machine restart gives.
The rig's P2 judge (`judge_p2`, shared by both columns) then required "died", the
worker-death wording of the process column, so the cell failed on that first oracle and
never checked the rest of P2 (no re-delivery, exactly one attempt, `/work` unchanged).
The record stays a `fail`. The judge now reads the settlement off the chain
(`judge_p2_settlement`), takes the restart's wording on the host column, and runs every
P2 oracle.

The rerun round ran the host column's `P1-host` (first, as a shakedown of the VM) and
`P2-host` once each, on `nanocode-anthropic`, on a fresh E9 VM, with
the fixed judge; both passed and neither is void. `P2-host`'s call was open at the kill
(`started 1, completed 0, open true` in kata's progress frames), kata settled the attempt
PROVEN AMBIGUOUS with "the main restarted … NOT re-delivered", and every P2 oracle held:
one attempt, one claim, one dispatch, no acceptance, `/work` unchanged, nothing landed,
pushed or opened, no container or cgroup left. The 0.0.1 round's `P2-host` `fail`
stays beside it, so the table counts both.

<!-- evidence:E3:begin -->
| Case | nanocode-openai | nanocode-anthropic |
|---|---|---|
| gate-main-kill | 1 pass of 1 run(s) | 1 pass of 1 run(s) |
| gate-worker-kill | 1 pass of 1 run(s) | 1 pass of 1 run(s) |
| P1 | 1 pass of 1 run(s) | 1 pass of 1 run(s) |
| P2 | 1 pass of 1 run(s) | 1 pass of 1 run(s) |
| P3 | 1 pass of 1 run(s) | 1 pass of 1 run(s) |
| P4 | 1 pass of 1 run(s) | 1 pass of 1 run(s) |
| P1-host | not yet run | 2 pass of 2 run(s) |
| P2-host | not yet run | 1 pass of 2 run(s) |
| P3-host | not yet run | 1 pass of 1 run(s) |
| P4-host | not yet run | 1 pass of 1 run(s) |

| Run | Case | Harness | Surface | kata | Vendor | Model (effort) | Tokens, kata | Tokens, provider | Cost, kata | Cost, provider | Wall | Outcome | Settlement, observed (expected) | Read from | Artifacts |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| [e3-P1-host-nanocode-anthropic-20261112T154232Z](runs/e3-P1-host-nanocode-anthropic-20261112T154232Z/run.toml) | P1-host | nanocode-anthropic | cli | `4da3b2fe2aa4` (tree `74133d703da4`) | nanocode `2ac77424e032` | claude-sonnet-5-5 (medium) | in 0 / cached 0 / cache-write 0 / out 0 (+0 call(s), usage unknown, in 1 unknown charge(s)) | unavailable: per-run provider usage not attributable | unavailable | unavailable: per-run provider usage not attributable | 13 s | **pass** | proven-ambiguous (expected proven-ambiguous) | oracle.txt: settled proven-ambiguous, every oracle held (expected proven-ambiguous) | [oracle.txt](runs/e3-P1-host-nanocode-anthropic-20261112T154232Z/oracle.txt), [sse-transcript.txt](runs/e3-P1-host-nanocode-anthropic-20261112T154232Z/sse-transcript.txt), [change.star](runs/e3-P1-host-nanocode-anthropic-20261112T154232Z/change.star), [tree.txt](runs/e3-P1-host-nanocode-anthropic-20261112T154232Z/tree.txt), [spend-ledger.toml](runs/e3-P1-host-nanocode-anthropic-20261112T154232Z/spend-ledger.toml) |
| [e3-P1-host-nanocode-anthropic-20261112T220927Z](runs/e3-P1-host-nanocode-anthropic-20261112T220927Z/run.toml) | P1-host | nanocode-anthropic | cli | `1dbee018d14f` (tree `2b6b523bc3c1`) | nanocode `2ac77424e032` | claude-sonnet-5-5 (medium) | in 0 / cached 0 / cache-write 0 / out 0 (+0 call(s), usage unknown, in 1 unknown charge(s)) | unavailable: per-run provider usage not attributable | unavailable | unavailable: per-run provider usage not attributable | 13 s | **pass** | proven-ambiguous (expected proven-ambiguous) | oracle.txt: settled proven-ambiguous, every oracle held (expected proven-ambiguous) | [oracle.txt](runs/e3-P1-host-nanocode-anthropic-20261112T220927Z/oracle.txt), [sse-transcript.txt](runs/e3-P1-host-nanocode-anthropic-20261112T220927Z/sse-transcript.txt), [change.star](runs/e3-P1-host-nanocode-anthropic-20261112T220927Z/change.star), [tree.txt](runs/e3-P1-host-nanocode-anthropic-20261112T220927Z/tree.txt), [spend-ledger.toml](runs/e3-P1-host-nanocode-anthropic-20261112T220927Z/spend-ledger.toml) |
| [e3-P1-nanocode-anthropic-20261112T151704Z](runs/e3-P1-nanocode-anthropic-20261112T151704Z/run.toml) | P1 | nanocode-anthropic | cli | `4da3b2fe2aa4` (tree `74133d703da4`) | nanocode `2ac77424e032` | claude-sonnet-5-5 (medium) | in 0 / cached 0 / cache-write 0 / out 0 (+0 call(s), usage unknown, in 1 unknown charge(s)) | unavailable: per-run provider usage not attributable | unavailable | unavailable: per-run provider usage not attributable | 13 s | **pass** | proven-ambiguous (expected proven-ambiguous) | oracle.txt: settled proven-ambiguous, every oracle held (expected proven-ambiguous) | [oracle.txt](runs/e3-P1-nanocode-anthropic-20261112T151704Z/oracle.txt), [sse-transcript.txt](runs/e3-P1-nanocode-anthropic-20261112T151704Z/sse-transcript.txt), [change.star](runs/e3-P1-nanocode-anthropic-20261112T151704Z/change.star), [tree.txt](runs/e3-P1-nanocode-anthropic-20261112T151704Z/tree.txt), [spend-ledger.toml](runs/e3-P1-nanocode-anthropic-20261112T151704Z/spend-ledger.toml) |
| [e3-P1-nanocode-openai-20261112T151403Z](runs/e3-P1-nanocode-openai-20261112T151403Z/run.toml) | P1 | nanocode-openai | cli | `4da3b2fe2aa4` (tree `74133d703da4`) | nanocode `2ac77424e032` | gpt-6-luna (medium) | in 0 / cached 0 / cache-write 0 / out 0 (+0 call(s), usage unknown, in 1 unknown charge(s)) | unavailable: a subscription login has no per-token view | unavailable | unavailable: subscription | 13 s | **pass** | proven-ambiguous (expected proven-ambiguous) | oracle.txt: settled proven-ambiguous, every oracle held (expected proven-ambiguous) | [oracle.txt](runs/e3-P1-nanocode-openai-20261112T151403Z/oracle.txt), [sse-transcript.txt](runs/e3-P1-nanocode-openai-20261112T151403Z/sse-transcript.txt), [change.star](runs/e3-P1-nanocode-openai-20261112T151403Z/change.star), [tree.txt](runs/e3-P1-nanocode-openai-20261112T151403Z/tree.txt), [spend-ledger.toml](runs/e3-P1-nanocode-openai-20261112T151403Z/spend-ledger.toml) |
| [e3-P2-host-nanocode-anthropic-20261112T154509Z](runs/e3-P2-host-nanocode-anthropic-20261112T154509Z/run.toml) | P2-host | nanocode-anthropic | cli | `4da3b2fe2aa4` (tree `74133d703da4`) | nanocode `2ac77424e032` | claude-sonnet-5-5 (medium) | in 8 / cached 19968 / cache-write 1264 / out 480 (+1 call(s), usage unknown, in 1 unknown charge(s)) | unavailable: per-run provider usage not attributable | unavailable | unavailable: per-run provider usage not attributable | 3 s | **fail** | proven-ambiguous (expected proven-ambiguous) | oracle.txt: an oracle did not hold: e3_crash_matrix_host_live: the settled attempt names the worker's death and its ambiguity: {"delivery":{"awaiting_approval_at_ms":null,"child_execution_id":null,"dispatched_at_ms":1794498317788,"finished_at_ms":1794498339349,"last_checkpoint":0,"stage_name":"implement","started_at_ms":1794498317815,"worker_id":"local-worker-0"},"reason":"the main restarted. PROVEN AMBIGUOUS: the main cannot observe whether this capsule's container ran, so the stage may have done anything it was asked. The attempt is settled terminal and NOT re-delivered (capsule re-delivery is not implemented)","terminal_charge":{"token_usage":{"cache_read":0,"cache_savings_micro_usd":0,"cache_write":0,"cost":{"backend":"nanocode_anthropic","model":"claude-sonnet-5-5","quality":"unavailable"},"input":0,"output":0}},"verdict":"proven_ambiguous"} (expected proven-ambiguous) | [oracle.txt](runs/e3-P2-host-nanocode-anthropic-20261112T154509Z/oracle.txt), [sse-transcript.txt](runs/e3-P2-host-nanocode-anthropic-20261112T154509Z/sse-transcript.txt), [change.star](runs/e3-P2-host-nanocode-anthropic-20261112T154509Z/change.star), [tree.txt](runs/e3-P2-host-nanocode-anthropic-20261112T154509Z/tree.txt), [spend-ledger.toml](runs/e3-P2-host-nanocode-anthropic-20261112T154509Z/spend-ledger.toml) |
| [e3-P2-host-nanocode-anthropic-20261112T221007Z](runs/e3-P2-host-nanocode-anthropic-20261112T221007Z/run.toml) | P2-host | nanocode-anthropic | cli | `1dbee018d14f` (tree `2b6b523bc3c1`) | nanocode `2ac77424e032` | claude-sonnet-5-5 (medium) | in 8 / cached 13965 / cache-write 7321 / out 601 (+1 call(s), usage unknown, in 1 unknown charge(s)) | unavailable: per-run provider usage not attributable | unavailable | unavailable: per-run provider usage not attributable | 13 s | **pass** | proven-ambiguous (expected proven-ambiguous) | oracle.txt: settled proven-ambiguous, every oracle held (expected proven-ambiguous) | [oracle.txt](runs/e3-P2-host-nanocode-anthropic-20261112T221007Z/oracle.txt), [sse-transcript.txt](runs/e3-P2-host-nanocode-anthropic-20261112T221007Z/sse-transcript.txt), [change.star](runs/e3-P2-host-nanocode-anthropic-20261112T221007Z/change.star), [recourse.txt](runs/e3-P2-host-nanocode-anthropic-20261112T221007Z/recourse.txt), [tree.txt](runs/e3-P2-host-nanocode-anthropic-20261112T221007Z/tree.txt), [spend-ledger.toml](runs/e3-P2-host-nanocode-anthropic-20261112T221007Z/spend-ledger.toml) |
| [e3-P2-nanocode-anthropic-20261112T151717Z](runs/e3-P2-nanocode-anthropic-20261112T151717Z/run.toml) | P2 | nanocode-anthropic | cli | `4da3b2fe2aa4` (tree `74133d703da4`) | nanocode `2ac77424e032` | claude-sonnet-5-5 (medium) | in 6 / cached 12828 / cache-write 1076 / out 443 (+1 call(s), usage unknown, in 1 unknown charge(s)) | unavailable: per-run provider usage not attributable | unavailable | unavailable: per-run provider usage not attributable | 18 s | **pass** | proven-ambiguous (expected proven-ambiguous) | oracle.txt: settled proven-ambiguous, every oracle held (expected proven-ambiguous) | [oracle.txt](runs/e3-P2-nanocode-anthropic-20261112T151717Z/oracle.txt), [sse-transcript.txt](runs/e3-P2-nanocode-anthropic-20261112T151717Z/sse-transcript.txt), [change.star](runs/e3-P2-nanocode-anthropic-20261112T151717Z/change.star), [recourse.txt](runs/e3-P2-nanocode-anthropic-20261112T151717Z/recourse.txt), [tree.txt](runs/e3-P2-nanocode-anthropic-20261112T151717Z/tree.txt), [spend-ledger.toml](runs/e3-P2-nanocode-anthropic-20261112T151717Z/spend-ledger.toml) |
| [e3-P2-nanocode-openai-20261112T151417Z](runs/e3-P2-nanocode-openai-20261112T151417Z/run.toml) | P2 | nanocode-openai | cli | `4da3b2fe2aa4` (tree `74133d703da4`) | nanocode `2ac77424e032` | gpt-6-luna (medium) | in 6740 / cached 0 / cache-write 0 / out 91 (+1 call(s), usage unknown, in 1 unknown charge(s)) | unavailable: a subscription login has no per-token view | unavailable | unavailable: subscription | 16 s | **pass** | proven-ambiguous (expected proven-ambiguous) | oracle.txt: settled proven-ambiguous, every oracle held (expected proven-ambiguous) | [oracle.txt](runs/e3-P2-nanocode-openai-20261112T151417Z/oracle.txt), [sse-transcript.txt](runs/e3-P2-nanocode-openai-20261112T151417Z/sse-transcript.txt), [change.star](runs/e3-P2-nanocode-openai-20261112T151417Z/change.star), [recourse.txt](runs/e3-P2-nanocode-openai-20261112T151417Z/recourse.txt), [tree.txt](runs/e3-P2-nanocode-openai-20261112T151417Z/tree.txt), [spend-ledger.toml](runs/e3-P2-nanocode-openai-20261112T151417Z/spend-ledger.toml) |
| [e3-P3-host-nanocode-anthropic-20261112T154320Z](runs/e3-P3-host-nanocode-anthropic-20261112T154320Z/run.toml) | P3-host | nanocode-anthropic | cli | `4da3b2fe2aa4` (tree `74133d703da4`) | nanocode `2ac77424e032` | claude-sonnet-5-5 (medium) | in 0 / cached 0 / cache-write 0 / out 0 (+2 call(s), usage unknown, in 1 unknown charge(s)) | unavailable: per-run provider usage not attributable | unavailable | unavailable: per-run provider usage not attributable | 13 s | **pass** | proven-ambiguous (expected proven-ambiguous) | oracle.txt: settled proven-ambiguous, every oracle held (expected proven-ambiguous) | [oracle.txt](runs/e3-P3-host-nanocode-anthropic-20261112T154320Z/oracle.txt), [sse-transcript.txt](runs/e3-P3-host-nanocode-anthropic-20261112T154320Z/sse-transcript.txt), [change.star](runs/e3-P3-host-nanocode-anthropic-20261112T154320Z/change.star), [tree.txt](runs/e3-P3-host-nanocode-anthropic-20261112T154320Z/tree.txt), [spend-ledger.toml](runs/e3-P3-host-nanocode-anthropic-20261112T154320Z/spend-ledger.toml) |
| [e3-P3-nanocode-anthropic-20261112T151736Z](runs/e3-P3-nanocode-anthropic-20261112T151736Z/run.toml) | P3 | nanocode-anthropic | cli | `4da3b2fe2aa4` (tree `74133d703da4`) | nanocode `2ac77424e032` | claude-sonnet-5-5 (medium) | in 0 / cached 0 / cache-write 0 / out 0 (+3 call(s), usage unknown, in 1 unknown charge(s)) | unavailable: per-run provider usage not attributable | unavailable | unavailable: per-run provider usage not attributable | 18 s | **pass** | proven-ambiguous (expected proven-ambiguous) | oracle.txt: settled proven-ambiguous, every oracle held (expected proven-ambiguous) | [oracle.txt](runs/e3-P3-nanocode-anthropic-20261112T151736Z/oracle.txt), [sse-transcript.txt](runs/e3-P3-nanocode-anthropic-20261112T151736Z/sse-transcript.txt), [change.star](runs/e3-P3-nanocode-anthropic-20261112T151736Z/change.star), [tree.txt](runs/e3-P3-nanocode-anthropic-20261112T151736Z/tree.txt), [spend-ledger.toml](runs/e3-P3-nanocode-anthropic-20261112T151736Z/spend-ledger.toml) |
| [e3-P3-nanocode-openai-20261112T151434Z](runs/e3-P3-nanocode-openai-20261112T151434Z/run.toml) | P3 | nanocode-openai | cli | `4da3b2fe2aa4` (tree `74133d703da4`) | nanocode `2ac77424e032` | gpt-6-luna (medium) | in 0 / cached 0 / cache-write 0 / out 0 (+3 call(s), usage unknown, in 1 unknown charge(s)) | unavailable: a subscription login has no per-token view | unavailable | unavailable: subscription | 40 s | **pass** | proven-ambiguous (expected proven-ambiguous) | oracle.txt: settled proven-ambiguous, every oracle held (expected proven-ambiguous) | [oracle.txt](runs/e3-P3-nanocode-openai-20261112T151434Z/oracle.txt), [sse-transcript.txt](runs/e3-P3-nanocode-openai-20261112T151434Z/sse-transcript.txt), [change.star](runs/e3-P3-nanocode-openai-20261112T151434Z/change.star), [tree.txt](runs/e3-P3-nanocode-openai-20261112T151434Z/tree.txt), [spend-ledger.toml](runs/e3-P3-nanocode-openai-20261112T151434Z/spend-ledger.toml) |
| [e3-P4-host-nanocode-anthropic-20261112T154420Z](runs/e3-P4-host-nanocode-anthropic-20261112T154420Z/run.toml) | P4-host | nanocode-anthropic | cli | `4da3b2fe2aa4` (tree `74133d703da4`) | nanocode `2ac77424e032` | claude-sonnet-5-5 (medium) | in 14 / cached 32968 / cache-write 2548 / out 746 | unavailable: per-run provider usage not attributable | estimated $0.0172 | unavailable: per-run provider usage not attributable | 3 s | **pass** | pr-opened-once (expected pr-opened-once) | oracle.txt: settled pr-opened-once, every oracle held (expected pr-opened-once) | [oracle.txt](runs/e3-P4-host-nanocode-anthropic-20261112T154420Z/oracle.txt), [sse-transcript.txt](runs/e3-P4-host-nanocode-anthropic-20261112T154420Z/sse-transcript.txt), [change.star](runs/e3-P4-host-nanocode-anthropic-20261112T154420Z/change.star), [tree.txt](runs/e3-P4-host-nanocode-anthropic-20261112T154420Z/tree.txt), [spend-ledger.toml](runs/e3-P4-host-nanocode-anthropic-20261112T154420Z/spend-ledger.toml) |
| [e3-P4-nanocode-anthropic-20261112T151755Z](runs/e3-P4-nanocode-anthropic-20261112T151755Z/run.toml) | P4 | nanocode-anthropic | cli | `4da3b2fe2aa4` (tree `74133d703da4`) | nanocode `2ac77424e032` | claude-sonnet-5-5 (medium) | in 12 / cached 25848 / cache-write 2392 / out 690 | unavailable: per-run provider usage not attributable | estimated $0.0155 | unavailable: per-run provider usage not attributable | 24 s | **pass** | pr-opened-once (expected pr-opened-once) | oracle.txt: settled pr-opened-once, every oracle held (expected pr-opened-once) | [oracle.txt](runs/e3-P4-nanocode-anthropic-20261112T151755Z/oracle.txt), [sse-transcript.txt](runs/e3-P4-nanocode-anthropic-20261112T151755Z/sse-transcript.txt), [change.star](runs/e3-P4-nanocode-anthropic-20261112T151755Z/change.star), [tree.txt](runs/e3-P4-nanocode-anthropic-20261112T151755Z/tree.txt), [spend-ledger.toml](runs/e3-P4-nanocode-anthropic-20261112T151755Z/spend-ledger.toml) |
| [e3-P4-nanocode-openai-20261112T151515Z](runs/e3-P4-nanocode-openai-20261112T151515Z/run.toml) | P4 | nanocode-openai | cli | `4da3b2fe2aa4` (tree `74133d703da4`) | nanocode `2ac77424e032` | gpt-6-luna (medium) | in 19088 / cached 47104 / cache-write 0 / out 910 | unavailable: a subscription login has no per-token view | unavailable | unavailable: subscription | 51 s | **pass** | pr-opened-once (expected pr-opened-once) | oracle.txt: settled pr-opened-once, every oracle held (expected pr-opened-once) | [oracle.txt](runs/e3-P4-nanocode-openai-20261112T151515Z/oracle.txt), [sse-transcript.txt](runs/e3-P4-nanocode-openai-20261112T151515Z/sse-transcript.txt), [change.star](runs/e3-P4-nanocode-openai-20261112T151515Z/change.star), [tree.txt](runs/e3-P4-nanocode-openai-20261112T151515Z/tree.txt), [spend-ledger.toml](runs/e3-P4-nanocode-openai-20261112T151515Z/spend-ledger.toml) |
| [e3-gate-main-kill-nanocode-anthropic-20261112T151637Z](runs/e3-gate-main-kill-nanocode-anthropic-20261112T151637Z/run.toml) | gate-main-kill | nanocode-anthropic | cli | `4da3b2fe2aa4` (tree `74133d703da4`) | nanocode `2ac77424e032` | claude-sonnet-5-5 (medium) | in 12 / cached 19804 / cache-write 8388 / out 614 | unavailable: per-run provider usage not attributable | estimated $0.0291 | unavailable: per-run provider usage not attributable | 12 s | **pass** | resumed-at-gate (expected resumed-at-gate) | oracle.txt: settled resumed-at-gate, every oracle held (expected resumed-at-gate) | [oracle.txt](runs/e3-gate-main-kill-nanocode-anthropic-20261112T151637Z/oracle.txt), [sse-transcript.txt](runs/e3-gate-main-kill-nanocode-anthropic-20261112T151637Z/sse-transcript.txt), [change.star](runs/e3-gate-main-kill-nanocode-anthropic-20261112T151637Z/change.star), [tree.txt](runs/e3-gate-main-kill-nanocode-anthropic-20261112T151637Z/tree.txt), [spend-ledger.toml](runs/e3-gate-main-kill-nanocode-anthropic-20261112T151637Z/spend-ledger.toml) |
| [e3-gate-main-kill-nanocode-openai-20261112T151258Z](runs/e3-gate-main-kill-nanocode-openai-20261112T151258Z/run.toml) | gate-main-kill | nanocode-openai | cli | `4da3b2fe2aa4` (tree `74133d703da4`) | nanocode `2ac77424e032` | gpt-6-luna (medium) | in 15656 / cached 46592 / cache-write 0 / out 723 | unavailable: a subscription login has no per-token view | unavailable | unavailable: subscription | 35 s | **pass** | resumed-at-gate (expected resumed-at-gate) | oracle.txt: settled resumed-at-gate, every oracle held (expected resumed-at-gate) | [oracle.txt](runs/e3-gate-main-kill-nanocode-openai-20261112T151258Z/oracle.txt), [sse-transcript.txt](runs/e3-gate-main-kill-nanocode-openai-20261112T151258Z/sse-transcript.txt), [change.star](runs/e3-gate-main-kill-nanocode-openai-20261112T151258Z/change.star), [tree.txt](runs/e3-gate-main-kill-nanocode-openai-20261112T151258Z/tree.txt), [spend-ledger.toml](runs/e3-gate-main-kill-nanocode-openai-20261112T151258Z/spend-ledger.toml) |
| [e3-gate-worker-kill-nanocode-anthropic-20261112T151650Z](runs/e3-gate-worker-kill-nanocode-anthropic-20261112T151650Z/run.toml) | gate-worker-kill | nanocode-anthropic | cli | `4da3b2fe2aa4` (tree `74133d703da4`) | nanocode `2ac77424e032` | claude-sonnet-5-5 (medium) | in 14 / cached 32985 / cache-write 2547 / out 764 | unavailable: per-run provider usage not attributable | estimated $0.0173 | unavailable: per-run provider usage not attributable | 13 s | **pass** | resumed-at-gate (expected resumed-at-gate) | oracle.txt: settled resumed-at-gate, every oracle held (expected resumed-at-gate) | [oracle.txt](runs/e3-gate-worker-kill-nanocode-anthropic-20261112T151650Z/oracle.txt), [sse-transcript.txt](runs/e3-gate-worker-kill-nanocode-anthropic-20261112T151650Z/sse-transcript.txt), [change.star](runs/e3-gate-worker-kill-nanocode-anthropic-20261112T151650Z/change.star), [tree.txt](runs/e3-gate-worker-kill-nanocode-anthropic-20261112T151650Z/tree.txt), [spend-ledger.toml](runs/e3-gate-worker-kill-nanocode-anthropic-20261112T151650Z/spend-ledger.toml) |
| [e3-gate-worker-kill-nanocode-openai-20261112T151334Z](runs/e3-gate-worker-kill-nanocode-openai-20261112T151334Z/run.toml) | gate-worker-kill | nanocode-openai | cli | `4da3b2fe2aa4` (tree `74133d703da4`) | nanocode `2ac77424e032` | gpt-6-luna (medium) | in 21906 / cached 26496 / cache-write 0 / out 750 | unavailable: a subscription login has no per-token view | unavailable | unavailable: subscription | 28 s | **pass** | resumed-at-gate (expected resumed-at-gate) | oracle.txt: settled resumed-at-gate, every oracle held (expected resumed-at-gate) | [oracle.txt](runs/e3-gate-worker-kill-nanocode-openai-20261112T151334Z/oracle.txt), [sse-transcript.txt](runs/e3-gate-worker-kill-nanocode-openai-20261112T151334Z/sse-transcript.txt), [change.star](runs/e3-gate-worker-kill-nanocode-openai-20261112T151334Z/change.star), [tree.txt](runs/e3-gate-worker-kill-nanocode-openai-20261112T151334Z/tree.txt), [spend-ledger.toml](runs/e3-gate-worker-kill-nanocode-openai-20261112T151334Z/spend-ledger.toml) |
<!-- evidence:E3:end -->

## E9: a clean machine

A fresh Ubuntu 24.04 virtual machine: install the documented prerequisites,
clone the commit under test, `cargo build --release --locked`, install, run
host setup, log in, then E1. Every documented step runs as written (a
deviation is a documentation defect, and is recorded), every `sudo` step is
listed, the time to the first run is recorded, and E1's oracles hold inside
the machine, seeded recall excepted (below).

`scripts/e9-vm.sh` makes the machine, and its header states each command and
refusal. The guest is a stock Ubuntu 24.04 server cloud image, pinned by
release and sha256 and used only after Canonical's signed `SHA256SUMS`
verifies it; E9 therefore measures the README on Ubuntu 24.04 Server as that
image installs it (it already carries git, curl and python3), not on a
desktop or minimal install. Each VM has its own qcow2 overlay, cloud-init seed
and ssh keys, and qemu comes from the nixpkgs that `flake.lock` pins. The
repository was private when E9 ran, so `push-bundle <rev>` brings the
commit under test in as a git bundle. E9's record keys on the commit; the
bundle's sha256, also recorded, checks only that one transfer, since two
bundles of one commit differ in their bytes. `install` reads this
repository's README at the bundled commit and runs its Requirements, Install
from source and Quickstart command blocks as written, one login shell per
section. It times every line, lists every `sudo` the guest's journal
recorded, and records the time to the first run and each line it ran
differently from the README: the clone of the bundle, the main started in the
background, and its own checks, the last of which installs `sqlite3` for E1's
read-only oracles (kata itself needs none). It also runs every line without a
terminal and with passwordless guest `sudo`, so a prompt that asks only on a
terminal does not ask; its summary states this. The README's Nix installer
line passes `--yes`, so that installer takes the same path either way. After
`install`, and right before E1, `push-token <file>` copies the owner's read-only forge token in as `GH_TOKEN` without printing it, and
refuses any file that is not the owner's own, mode 0600; `drop-token` deletes
it right after E1. `install`, the E3 rig's build (`e3-prep`) and each E3 host
cell refuse to run on a guest that holds the token, so no install step, rig
build or host cell runs with it in its environment. The guest's agent logs in after `install`, also right before E1,
with kata's own login: on `nanocode-anthropic`, `login-anthropic` streams the
operator's `ANTHROPIC_API_KEY`, read from its own environment and never printed,
into the guest's `kata login anthropic --api-key`, so no browser is involved; on
`nanocode-openai`, the owner runs `kata login openai --device-code` inside the
guest over the script's `ssh`, in the owner's own terminal. The script takes
the key out of its own environment before it starts anything: qemu, the ssh
control master and every ssh and nix client it starts get only `PATH`, `HOME`
and `TERM`, and no process it starts has the key in its environment.

E9 passes when every install section exits 0 (the last one reads the
Quickstart's run `completed` through a second, read-only handle), the guest's
node boots the bundled commit built clean, and E1's oracles hold except seeded
recall: its seven other oracles pass, and its review validates (the schema's
shape, every finding on a path at the pull request's head). The seeded recall
is recorded as observed, never a pass condition: E9 measures the clean-machine
path, and recall is the model's, which E1 reports per harness. This rule was
fixed before any E9 run spent; `round-0.0.1/e9-verdict.py` generates the verdict
from those files, and the record's `outcome_source` reads `e9-verdict.txt:`
and its first line.

The 0.0.1 round ran E9 once, on `nanocode-anthropic` under kata's own
`anthropic-api-key` login, on a fresh VM. The `nanocode-openai`
case, whose login needs the owner's device-code sign-in in the guest, was not run.

<!-- evidence:E9:begin -->
| Case | nanocode-openai | nanocode-anthropic |
|---|---|---|
| clean-vm | not yet run | 1 pass of 1 run(s) |

| Run | Case | Harness | Surface | kata | Vendor | Model (effort) | Tokens, kata | Tokens, provider | Cost, kata | Cost, provider | Wall | Outcome | Read from | Artifacts |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| [e9-clean-vm-nanocode-anthropic-20261112T152049Z](runs/e9-clean-vm-nanocode-anthropic-20261112T152049Z/run.toml) | clean-vm | nanocode-anthropic | cli | `4da3b2fe2aa4` (tree `74133d703da4`) | nanocode `2ac77424e032` | claude-sonnet-5-5 (medium) | in 14 / cached 30038 / cache-write 14239 / out 1769 | unavailable: per-run provider usage not attributable | estimated $0.0563 | unavailable: per-run provider usage not attributable | 803 s | **pass** | e9-verdict.txt: pass: install 4 of 4 sections rc 0; boot check ok; E1 7 of 7 non-recall oracles PASS, the review validates (structure, paths); seeded recall 3/3 recorded, not judged | [e9-verdict.txt](runs/e9-clean-vm-nanocode-anthropic-20261112T152049Z/e9-verdict.txt), [summary.txt](runs/e9-clean-vm-nanocode-anthropic-20261112T152049Z/summary.txt), [plan.tsv](runs/e9-clean-vm-nanocode-anthropic-20261112T152049Z/plan.tsv), [timing.tsv](runs/e9-clean-vm-nanocode-anthropic-20261112T152049Z/timing.tsv), [guest-sudo.txt](runs/e9-clean-vm-nanocode-anthropic-20261112T152049Z/guest-sudo.txt), [sections.tsv](runs/e9-clean-vm-nanocode-anthropic-20261112T152049Z/sections.tsv), [README.md](runs/e9-clean-vm-nanocode-anthropic-20261112T152049Z/README.md), [bundle.env](runs/e9-clean-vm-nanocode-anthropic-20261112T152049Z/bundle.env), [e9-e1/boot-check.txt](runs/e9-clean-vm-nanocode-anthropic-20261112T152049Z/e9-e1/boot-check.txt), [e9-e1/doctor.txt](runs/e9-clean-vm-nanocode-anthropic-20261112T152049Z/e9-e1/doctor.txt), [e9-e1/config-check.txt](runs/e9-clean-vm-nanocode-anthropic-20261112T152049Z/e9-e1/config-check.txt), [e9-e1/host-setup.txt](runs/e9-clean-vm-nanocode-anthropic-20261112T152049Z/e9-e1/host-setup.txt), [e9-e1/ev/oracles.txt](runs/e9-clean-vm-nanocode-anthropic-20261112T152049Z/e9-e1/ev/oracles.txt), [e9-e1/ev/score.json](runs/e9-clean-vm-nanocode-anthropic-20261112T152049Z/e9-e1/ev/score.json), [e9-e1/ev/score-row.txt](runs/e9-clean-vm-nanocode-anthropic-20261112T152049Z/e9-e1/ev/score-row.txt), [e9-e1/ev/stages.txt](runs/e9-clean-vm-nanocode-anthropic-20261112T152049Z/e9-e1/ev/stages.txt), [e9-e1/ev/turns.txt](runs/e9-clean-vm-nanocode-anthropic-20261112T152049Z/e9-e1/ev/turns.txt), [e9-e1/ev/spend.toml](runs/e9-clean-vm-nanocode-anthropic-20261112T152049Z/e9-e1/ev/spend.toml) |
<!-- evidence:E9:end -->
