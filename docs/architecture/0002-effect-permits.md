# ADR 0002: Effect permits at the main's effect doors

- Status: Proposed — after 0.0.1; decisions 1 to 4 amended by ADR 0003 ("What this
  amends"); implemented at one door only, the forge export's push and pull request
  (ADR 0003's stage E1), and not accepted there: the ledger has no property per
  guarantee, and no crash cell follows the recording of the pull request's receipt (see
  "Consequences and acceptance"); the model request's door is owed to ADR 0003's stage S3
- Date: 2026-10-22
- Scope: per-effect exactly-once records for effects the main performs or adopts

## Context

kata settles work at the granularity of an attempt. Every attempt ends in one
recorded settlement, and that settlement says what the main can prove about the
attempt's effects:

- **Completed.** The attempt's outcome is accepted, at most once per occurrence,
  and replays from the record; a recovered run never runs an accepted stage again.
- **PROVEN NOT PERFORMED.** No frame for the attempt can have reached a worker, or
  the worker refused before anything ran. Redoing the work cannot perform an effect
  twice, so the stage's failure-retry chain may run it again.
- **PERFORMED BUT FAILED.** The process ran and the stage failed; its effects are a
  fact, and a retry is a new attempt.
- **PROVEN AMBIGUOUS** (and an unclassified failure, treated the same way). The main
  cannot tell whether the work ran — a worker that died mid-run, a lost deadline, a
  crash between placement and send. The attempt is never re-run automatically: the
  run fails, naming the verdict, and the operator decides.

Two mechanisms make most effects safe without anything finer. Trees the main lands
are content-addressed: a `/work` delta is applied by content into the CAS and the
execution's work-tree head, and a workspace effect (park, promote, commit, forge
export) runs in the main as a jj operation tagged with its attempt, so a crash
mid-effect is classified from the repository rather than performed again. When this
ADR was written, a forge export reconciled its push from the remote ref and looked for
an open pull request on the execution's branch before it opened one.

This is honest and it is coarse. The unit of uncertainty is a whole attempt, and
the only recourse for an ambiguous one is a human.

## Problem

Some effects are not idempotent by nature: opening a forge pull request, a push that
triggers CI, a notification. Where kata has no way to look the effect up afterwards,
a crash between performing it and recording that it was performed leaves the attempt
PROVEN AMBIGUOUS. Re-running it risks a duplicate the outside world keeps; not
re-running it risks an effect that never happened. Either way an operator has to look
outside kata and decide, and nothing durable says which effect, of which attempt, was
in flight. Where a lookup existed when this ADR was written — the forge export's
open-pull-request check — it was a per-door convention keyed on a name the door chose,
not a rule the engine enforces for every effect it performs.

## Decision (proposed)

1. **End-to-end scope.** Permits exist only at doors the main performs or adopts. An
   effect that is idempotent by content — a CAS object, a jj or git tree landed by
   content — needs no permit. An effect inside a capsule, such as an agent's own call
   to an external API, is out of scope: the main can neither gate nor observe it, so a
   permit there would record a claim nothing can check. *As amended by ADR 0003:* an
   embedded-harness model request is no longer such a call — it leaves the capsule
   through the gateway, a door kata gates and records (ADR 0003's stage S3, not yet
   built); any other call an agent makes from inside a capsule stays out of scope.
2. **Identity from deterministic coordinates.** A permit's identity is derived from
   the program's coordinates — execution, stage, attempt, and the effect's index
   within the attempt — and is minted where the effect originates, the way a sync
   engine mints a mutation id. A replay derives the same identity, so it finds the
   permit rather than minting a second one. *As amended by ADR 0003:* this holds for a
   push, a pull request and a comment; a model request's mark is the named exception,
   minted by the gateway and never re-issued. The forge export's push and pull request
   carry it today: one `forge_intents` row per wire effect, keyed `(attempt, effect
   index)` beside its execution and stage. A replay does not derive that index: it is
   the attempt's next when the intent is recorded, and a recovery reads the attempt's
   rows to find the intent a crashed drive left, so it answers that intent rather than
   minting a second.
3. **Written with the effect, not beside it.** *As amended by ADR 0003:* a wire
   effect's record splits into an INTENT and a RECEIPT. The intent is written as late
   as possible — after every step that can fail without issuing the effect, immediately
   before its first byte — and the receipt in the transaction that records the effect's
   result. After a crash, no intent means PROVEN NOT PERFORMED, an intent with a receipt
   the recorded outcome, and an intent alone is ambiguous until its observer (decision
   4) can say; nothing is redone under it. No protocol removes that interval, so kata
   keeps it short and per effect. The forge export implements this for its push and its
   pull request: the push's intent follows a read of the remote's head, whose answer is
   the push's lease (a failed read records no intent, so the export fails PROVEN NOT
   PERFORMED), and the push's PERFORMED verdict commits on its own before the pull
   request's lookup, so the pull request's intent commits alone. A model
   request's intent is written at the door by the gateway and adopted before any verdict
   depends on it, slices escrowing its bounds (ADR 0003 §5, its own stage).
4. **An observer per effect kind, before any reconcile.** Each effect kind states
   whether the main can determine that the effect happened, and how. A reconcile
   surface exists only for kinds with an observer: reconcile is accept or abandon,
   decided by the observer or, where the kind admits it, by an attributed operator.
   *As amended by ADR 0003:* a model request has no observer. A push's observer is the
   remote ref: PERFORMED at the intent's commit, NOT PERFORMED only while the ref still
   holds the intent's lease, and anything else unclassified at once (ADR 0003's checked
   model, finding F9). Its residual is stated: a ref back on the lease after kata's push
   landed and before its PERFORMED verdict commits (a crash before the receipt, then a
   move before the observer's first answered read), by any path, branch deletion
   included, reads NOT PERFORMED and the push is issued again. A pull request's observer
   matches the intent's marker in its body, in any state, open, closed or merged; a
   marker deleted from a pull request that is no longer open yields a second one. A
   read the remote does not answer settles neither observer: the intent stays open for
   a bounded re-ask, and its reconcile surface, `kata run forge-reconcile`, is one more
   ask, decided by the observer (ADR 0003 "Effects"). Both
   observers assume the effect's command died with a crashed main, as the shipped
   service unit makes it (it kills the main's control group before it restarts), and a
   command killed at its timeout is observed at once: a remote still applying it is
   recorded NOT PERFORMED — a wrong record, never a second effect, since that verdict
   after a failed command issues nothing again.
5. **Specification first.** The attempt, settlement and permit state machine is
   specified as a TLA+ model (or an equivalent checked model) and model-checked
   before it is implemented.

## Consequences and acceptance

- The protected-properties ledger gains a property per guarantee — at most one
  performed effect per permit identity; no effect issued before its intent commits, and
  no receipt outside the transaction that records the effect's result (decision 3 as
  amended: an intent may stand with no effect, and its observer answers it); no
  automatic re-performance of an effect whose intent has no verdict — each pinned by a
  cell that reads the outcome from outside kata.
- A crash cell at every boundary: before the permit is issued, after issue and before
  the effect, after the effect and before it is recorded, and after it is recorded.
- Operator surfaces (evidence, reconcile) ship only together with an observer for
  the effect kind they act on.

## Non-goals

- Exactly-once for effects inside a capsule.
- Replacing attempt-level settlement: permits refine it for the doors they cover.
- A generic retry policy for non-idempotent effects.

## Alternatives considered

- **Keep the pre-0.0.1 side-ledger permit plane.** Rejected. Production never issued
  a permit; the claim key encoded no effect identity finer than the attempt; its
  reconcile surface had a probe for one effect kind only, which could show that an
  effect happened but never that it did not; and the table was a side ledger written
  apart from the effect, so it could drift from the effect it described.
- **Rely on attempt-level settlement alone.** This is the current state. It is
  correct but leaves every non-idempotent main-side effect to an operator after a
  crash.

## Prior implementation

An earlier, unwired permit plane was removed before 0.0.1; it remains in the project
history.

## Open questions

- Which effect doors come first. *Answered by ADR 0003:* the forge export's push and
  pull request (its stage E1, implemented), then the model requests' marks (its stage
  S3).
- The observer contract for each forge. *Answered for GitHub by E1:* a push is proven
  by `git ls-remote` of the branch against the intent's commit and lease; a pull
  request by `gh pr list --repo <HOST/OWNER/REPO> --head <branch> --state all` — the
  repository the push remote's URL names — and the intent's coordinates in its body
  (`<!-- kata-forge-intent: <attempt>/<index> -->`), only a pull request whose head is
  in that repository (not a fork's branch of the same name) counted, the listing
  bounded and a listing at its bound proving no absence.
