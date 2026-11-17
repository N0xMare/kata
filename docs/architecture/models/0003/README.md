# ADR 0003: the checked model

The TLA+ model plan M0 owes before node session v2 (S2's lease, incarnation, intake and
`Resume`), the gateway's slices (S3's L3b) and forge intents merge: the node session,
the provider-owned kill, settlement, the gateway's escrowed slices and marks, data
generations, restore, the revocation mirror, and the ingress fence. `checks.toml` names
every TLC run and the verdict it must reach; `just model-check-0003` runs them
([verification.md](../../../development/verification.md#the-checked-models) states the
manifest's rules and what a green does and does not say).

## Modules

| Module | ADR 0003 | Invariants |
|---|---|---|
| `LeaseOrder.tla` | §4 node session; §5 settlement; §3 revocation at the gateway | `NoCapsuleAfterSettlement` (the subtree is empty before settlement, outside the named steps); `NoDoubleDelivery` (an attempt delivered at most once; a stage never in two capsules); `NotPerformedIsSound`; `PastGKeepsReportedOutcome`; `NoMarkOnClosedSliceOrRevokedNode` (no mark once kata-control holds the slice's `SliceClosed`, or once the gateway's mirror holds the node's revocation); `NoMarkAfterRevokeCommitted` (§3's "from then on", literally; refuted, F4); `VerdictsOnlyForward`; `TypeOK` |
| `SliceBudget.tla` | §5 slices, marks, adoption, bounds | `NoRefillWhenFrozen`; `SpendWithinBoundPlusInFlight`; `NoForwardPastTheBound` (§5's bound claim, literally; refuted, F2); `NoReissue`; `NoForwardWithoutMark`; `NotPerformedIsSound`; `PastGAmbiguousOnlyUnreported`; `ChargeNeverZeroForUnknown`; `AdoptionComplete`; `NewSliceAfterOwedRevokes`; `NoMarkOnClosedSlice` (no mark once kata-control holds the slice closed, or lost with its journal's generation) |
| `Restore.tla` | §2 identity, generations, the revocation mirror; §10 backup and restore | `RevokedNeverWelcomed`; `NoRepeatWithoutOperator`; `NoCapsuleAfterSettlement`; `OneCapsulePerStage` |
| `FenceExemption.tla` | §4 fencing; plan S2 L2b ("the NULL-placement exemption per M0") | `NoForeignFrameAccepted`; `NoGenuineTerminalRefused` |
| `ForgeIntent.tla` | "Effects"; E1 forge intents behind the pre-intent read and the pull request's lookup; the observers' bounded re-ask | `NoWireEffectWithoutIntent`; `NoPushOverUnreadHead`; `NoPushWithoutVerdict`; `OnePullRequest` (a deleted marker on a pull request no longer open excepted); `ObserverVerdictSound`; `NotPerformedIsSound`; `NoUnclassifiedBeforeTheBound` (an unanswered read settles nothing before `MaxAsks`); `NoAskPastTheBound` (the count and its settlement two steps, the drive's pre-check between them); `BeyondBoundSettlesAtOnce` (a marker listing past its bound is UNCLASSIFIED at once, never counted unanswered) |

## How the model is built

- **Time is relative.** Every clock fact is a countdown to a deadline or an age capped
  where it stops mattering, so the state space is finite with no horizon: the checks
  hold for unbounded time. An obligation (the provider's kill by `D + K`, a live node's
  containment by `K_CONTAIN`) blocks time from passing its deadline.
- **Drift is widened.** A duration `d` on a clock drifting by `rho` against real time
  takes a real duration in `[d/(1+rho), d/(1-rho)]`; the model rounds that interval
  outward, which only adds behaviours. The `lease-order-drift*` checks run
  `rho = 1/10`; the other LeaseOrder checks run exact clocks.
- **Faults are budgeted.** Each check gives the adversary `MaxFaults` moves (stall, crash,
  partition, provider death, suspend, control or gateway restart, a lost data directory,
  revocation) from the set its `ALLOW_*` constants enable; recoveries are free. The
  `*-fault-pairs` checks enable every fault of their module, two per behaviour.
- **The gateway keeps its own records.** It closes a slice in its journal when it
  processes `SliceRevoke`, and learns a revocation over its session with kata-control,
  after the commit; kata-control's slice record and its `revoked` row are separate
  variables, so a mark check holds only through the order the ADR gives those steps.
- **The harness goes on.** A turn whose stream the gateway cut or lost keeps asking;
  under `HARNESS_RETRIES` it re-sends the request that failed, as nanocode's retry
  layers do. The gateway's checks are what refuse it.
- **Named steps are excused.** A capsule that lives through a double fault or a suspend
  is outside `NoCapsuleAfterSettlement`, as §4 states it.
- **Nodes are interchangeable.** The `lease-order-two-nodes*` checks reduce by
  permuting them (TLC's `SYMMETRY`): every LeaseOrder invariant and property is
  unchanged by renaming nodes, so the reduction keeps every violation.
- **Ground truth is a ghost.** SliceBudget's mark `usage` is what upstream really
  processed, Unknown marks and a lost journal's included; kata reads it only through
  Completed terminals.
- A check that names a constant overrides only that constant; the rest are the spec's.

## Assumed

Each was a sentence ADR 0003's draft did not state outright, and the ADR now states each
(§2, §3, §4); the mutant named removes it and the check named reaches a violation without
it, so the model's passes rest on it.

| Assumption | Mutant | Rests on it |
|---|---|---|
| `kata-node join <token>` mints the node's key (§3), so a key is admitted at most once and a revoked key never rejoins | none: the model admits a key once | every Restore admission check |
| The no-mirror restore's key drop is an `admission.db` write, so it advances the registry's monotonic sequence (§2) | `drop_without_seq_bump` | `restore-corrected-admission` |
| A restore is a boot: the restored store's open attempts settle only after `W` from boot (§2 says only "settles ... AMBIGUOUS") | `restore_settles_at_boot` | `restore-as-written`, `restore-corrected-work` |
| A restored kata-control refuses `Resume` of an incarnation an older generation welcomed (§4 names only an already-settled one), so an older generation's capsule gets no further grant | `resume_across_restore` | `restore-as-written`, `restore-corrected-work` |

## Findings

Each is a check that pins the counterexample to ADR 0003's draft as it stood
(`finding = "<id>"` in `checks.toml`); the ADR now states each correction where the rule
it corrects is, naming the finding.

| Id | Check | What broke, as the draft stood |
|---|---|---|
| F1 | `lease-order-finding-containment-outside-w` | §4 pins `K` (the provider, `D` to an empty subtree) below the slack and claims the order against "a provider that dies under a live node"; a provider that dies just before its kill hands the capsule to the node's `kill_and_contain`, whose latency no term of `W` covers. |
| F2 | `slice-budget-finding-sibling-overshoot` | §5's bound claim: the gateway checks each slice's own grant, so once one sibling's request overshoots and the scope's known usage reaches its bound, a sibling still holding escrowed grant is forwarded. |
| F3 | `slice-budget-finding-harness-retries` | §1/§5 "never re-issued": kata runs nanocode's retry layers (Responses: 5 tries by default; Messages: 5, or 3 without tools, fixed in the backend, which no `max_attempts` reaches), and under `time_bound` the harness re-sends, under a new mark, a request whose stream failed before a response reached it: upstream's transient pre-output failure or a gateway crash (`Unknown{gateway_lost}`), each possibly processed. The fix is at kata's host transport and the gateway, on both backends: every `Unknown` reaches the harness as `x-should-retry: false`. |
| F4 | `restore-finding-revocation-rolled-back`, `lease-order-finding-mark-after-revoke-commit` | §2 "revocations do not roll back" and §3 "from then on ... the gateway refuses the node's requests": `kata node revoke` reports success at the `admission.db` commit, before the gateway's mirror holds it. A data loss in between, and the restore welcomes the key; and until the mirror holds it (while the gateway's session with kata-control is down, up to the open slices' grants and deadlines), the revoked node's requests are marked and forwarded. Correction: report success only once the mirror holds it. |
| F5 | `restore-finding-resume-beside-orphan` | §10 holds restored work for the operator but nothing holds a resume until `W` from boot: the stage runs again beside a capsule the backup does not know. |
| F6 | `restore-finding-sequence-adoption-write` | §2 adopts the mirror by sequence and orders only `Hello` after the gateway's answer: a join after the restore makes the mirror look not newer, and a mirrored revocation is lost. Correction: hold every admission write until the gateway answers. |
| F7 | `lease-order-finding-dead-provider-under-crashed-node` | §4 names one double fault (a dead provider under a STALLED node); a dead provider under a CRASHED node has no kill path either. |
| F8 | `fence-finding-exemption-kept` | Keeping the NULL-placement exemption once the placement commits in the dispatch transaction lets any admitted node's frame through at a parked attempt's epoch; `fence-placement-in-dispatch` shows it can go. |
| F9 | `forge-intent-finding-aba` | The push's observer is the remote ref: a branch back on the very head kata leased on, by any path after kata's push and before its observer's first answered read (deleted, when kata found it absent), reads NOT PERFORMED and the push is sent again; unstated beside the marker residual. The code writes that answer, like the push's receipt, before the pull request's lookup (`PushReceipt` and the observer's verdict both precede `LookupPR`), so a main lost inside the lookup asks no observer again. A read error's re-ask keeps the window open while the remote is down; a contradicting answer closes it, settling UNCLASSIFIED at once (`contradiction_reasked` is the mutant). |
| R1 | `fence-today-residual` | Today's code: the exemption's stated residual (a forged frame at an unplaced attempt's epoch passes). |

The passing checks named `*-corrected-*` run Restore with the corrections F4 to F6 call
for: a revocation reported only once the gateway's mirror holds it (F4), every
admission write of a restored control plane held until the gateway answers (F6), and
every dispatch held until `W` from boot (F5). With those, the ADR's own adoption by
sequence keeps a revoked key out across two restores, a no-mirror one between them.
LeaseOrder's passing checks hold `NoMarkOnClosedSliceOrRevokedNode`, read on the
gateway's mirror: with F4's correction no mark follows a reported revocation.

ForgeIntent models the push observer as NOT PERFORMED only while the ref still holds
the lease (anything else but kata's commit is unclassified); a naive observer that reads
any other head as NOT PERFORMED is a mutant (`naive_push_observer`). A push the remote
refuses because the branch moved off its lease leaves its intent open with the command's
error, and the observer judges it as the code's `observed_push` does: UNCLASSIFIED while
the branch holds another head, and NOT PERFORMED only once it is back on the lease, which
then fails the export instead of pushing again. An observer read the
remote does not answer leaves the intent open, counted on it, and an intent counted
`MaxAsks` times is settled UNCLASSIFIED in a step of its own, as the code settles it in a
second transaction, and is never asked again (`unread_is_unclassified`, the code before
owner decision #15, `unbounded_reask` and `ask_at_bound`, the drive without its
pre-check, are the mutants). A marker listing that reaches its bound on a head crowded
with pull requests answers neither way and settles UNCLASSIFIED at once
(`beyond_bound_unanswered` counts it as unanswered instead). The model has no clock,
so the code's spacing between asks and `kata run forge-reconcile`'s out-of-schedule ask
are both just an ask.
The pull request's lookup before its intent adopts an open pull request on kata's head,
the marker deleted included (`no_pr_lookup` and `unread_lookup_is_none` are the
mutants); a failed lookup ends the export `pr_unread`, the push standing.

## Not modeled here

Nested bounded scopes (one scope here); several nodes beside an embedded-harness attempt
(the `lease-order-two-nodes*` checks run shell attempts and one fault, a second
incarnation per node only at `L = 2`; every other LeaseOrder check runs one node);
intermittent nodes (the future ADR); the content protocol; the effects worker's own
process boundary.
