----------------------------- MODULE SliceBudget -----------------------------
(***************************************************************************)
(* ADR 0003 §5 (model egress) as a checked model. kata-control escrows a   *)
(* per-attempt slice from a bounded scope in the dispatch transaction and  *)
(* refills it from the undebited remainder; the gateway checks each        *)
(* request against its slice, commits a mark before the first upstream     *)
(* byte, and ships terminals to kata-control asynchronously, adopted       *)
(* idempotently by (generation, sequence); settlement sends SliceRevoke    *)
(* and waits for SliceClosed or G; unclosed and lost slices and adopted    *)
(* Unknown marks freeze the scope; SliceRevoke is resent first on every    *)
(* reconnect; a gateway restart turns open marks Unknown{gateway_lost}; a  *)
(* lost gateway journal is a new gateway generation.                       *)
(*                                                                         *)
(* GROUND TRUTH. Each mark's `usage` is what upstream really processed and *)
(* bills, Unknown marks and marks of a lost journal included. kata reads   *)
(* it only through Completed terminals; the invariants read it whole.      *)
(*                                                                         *)
(* One scope (BOUNDED: token-bounded with bound B; otherwise time_bound    *)
(* alone), sibling attempts each holding one slice, each attempt's harness *)
(* sending up to MaxReq logical requests one at a time. A request's usage  *)
(* is any value in 1..UMAX: a Responses request carries no mandatory       *)
(* output cap, so one request may overshoot its slice's grant.             *)
(*                                                                         *)
(* The control <-> gateway session is one ordered stream: a message sent   *)
(* earlier on it is processed first, so a grant cannot overtake an earlier *)
(* SliceRevoke. A dropped session loses what was in flight.                *)
(*                                                                         *)
(* MUTANT selects one deliberate defect; the real model is "none".         *)
(* HARNESS_RETRIES is not a mutant: TRUE is nanocode's own retry layers as *)
(* kata runs them today (Responses: `ResponsesRetryPolicy`, 5 tries;       *)
(* Messages: 5, or 3 without tools, fixed in the backend), which re-send a *)
(* request whose stream failed before any response reached the harness:    *)
(* upstream's transient failure, a gateway crash, a SliceRevoke cut.       *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences

CONSTANTS
    Attempts,       \* sibling attempts in the one scope
    MaxReq,         \* logical model requests per attempt's turn
    BOUNDED,        \* TRUE: a token-bounded scope with bound B; FALSE: time_bound alone
    B,              \* the scope's bound
    CHUNK,          \* a grant or refill is min(remaining, CHUNK)
    UMAX,           \* largest usage of one request
    MaxMarks,       \* bound on marks journaled (model-checking bound)
    HARNESS_RETRIES,\* the harness re-sends a request that failed before any output
    ALLOW_GW_CRASH, ALLOW_GW_LOSS, ALLOW_LINK_LOSS, ALLOW_CTL_CRASH,
    MaxFaults,
    MUTANT

Mutants == {"none",
            "no_unknown_freeze",        \* the gateway forwards past an Unknown in its scope
            "refill_ignores_remainder", \* a refill not drawn from the undebited remainder
            "refill_despite_unclosed",  \* kata-control refills a scope holding an unclosed slice
            "unclosed_in_memory",       \* "unclosed" kept only in memory: lost at a restart
            "ignore_gateway_generation",\* a new gateway generation's lost slices not noticed
            "no_slice_revoke_resend",   \* SliceRevoke not resent on a reconnect
            "settle_before_slice_close",\* the verdict read before SliceClosed
            "past_g_drops_outcome",     \* past G a reported outcome is dropped for AMBIGUOUS
            "mark_after_first_byte",    \* the mark is committed after forwarding starts
            "charge_from_adopted",      \* the charge read from shipped terminals, not SliceClosed
            "adopt_by_seq_only",        \* adoption keyed by sequence alone, not (generation, sequence)
            "gateway_reissues_unknown", \* the gateway re-sends a request that ended Unknown
            "admit_on_closed_slice"}    \* the mark check skips "the slice is open"

ASSUME MUTANT \in Mutants

Reqs == 1 .. MaxReq
NoGrant == -1   \* time_bound: a slice with no grant to check

VARIABLES
    \* ---- kata-control (durable unless noted) ----
    remaining,      \* undebited remainder of the bound
    grant,          \* [Attempts -> Int] the slice's escrowed grant
    cSlice,         \* [Attempts -> "none"|"open"|"revoking"|"closed"|"unclosed"|"lost"]
    sliceGen,       \* [Attempts -> Nat] the gateway generation that journaled the slice
    adopted,        \* adoption keys
    unknownAdopted, \* [Attempts -> BOOLEAN] an Unknown mark of the slice was adopted
    reported,       \* [Attempts -> BOOLEAN] the node reported an outcome
    verdict,        \* [Attempts -> "-"|"NOT_PERFORMED"|"OUTCOME"|"AMBIGUOUS"]
    charge,         \* [Attempts -> "-"|"exact"|"unknown"]
    cUp,
    unclosedMem,    \* the mutant's in-memory set of unclosed slices
    \* ---- gateway ----
    gUp, gGen,
    gSlice,         \* [Attempts -> [gen, open, grant]] the journal's slices (gen 0: none)
    marks,          \* every mark ever journaled, every generation's
    gSeq,           \* next mark sequence in the current generation
    \* ---- the control <-> gateway session ----
    link,
    revokePending,  \* [Attempts -> BOOLEAN] a SliceRevoke in flight to the gateway
    closedAnswer,   \* [Attempts -> BOOLEAN] a SliceClosed in flight to kata-control
    \* ---- harness ----
    next,           \* [Attempts -> Nat] the logical request the harness is on
    waiting,        \* [Attempts -> BOOLEAN] its request is in flight
    done,           \* [Attempts -> BOOLEAN] the turn is over
    \* ---- ghosts ----
    shipped,        \* <<gen, seq>> of every terminal the gateway shipped
    sends,          \* [Attempts -> [Reqs -> Nat]] upstream forwards per logical request
    rejectedSends,  \* of those, ended Rejected
    badForward,     \* a request forwarded where ADR §5's bound claim says none is
    badGrant,       \* a slice journaled while one owed a SliceRevoke was still open
    markOnClosed,   \* a mark journaled on a slice kata-control holds closed or lost
    faults

ctl == <<remaining, grant, cSlice, sliceGen, adopted, unknownAdopted, reported, verdict,
         charge, cUp, unclosedMem>>
gw == <<gUp, gGen, gSlice, marks, gSeq>>
session == <<link, revokePending, closedAnswer>>
harness == <<next, waiting, done>>
ghost == <<shipped, sends, rejectedSends, badForward, badGrant, markOnClosed>>
vars == <<ctl, gw, session, harness, ghost, faults>>

Init ==
    /\ remaining = IF BOUNDED THEN B ELSE 0
    /\ grant = [a \in Attempts |-> 0]
    /\ cSlice = [a \in Attempts |-> "none"]
    /\ sliceGen = [a \in Attempts |-> 0]
    /\ adopted = {}
    /\ unknownAdopted = [a \in Attempts |-> FALSE]
    /\ reported = [a \in Attempts |-> FALSE]
    /\ verdict = [a \in Attempts |-> "-"]
    /\ charge = [a \in Attempts |-> "-"]
    /\ cUp = TRUE
    /\ unclosedMem = {}
    /\ gUp = TRUE
    /\ gGen = 1
    /\ gSlice = [a \in Attempts |-> [gen |-> 0, open |-> FALSE, grant |-> 0]]
    /\ marks = << >>
    /\ gSeq = 1
    /\ link = TRUE
    /\ revokePending = [a \in Attempts |-> FALSE]
    /\ closedAnswer = [a \in Attempts |-> FALSE]
    /\ next = [a \in Attempts |-> 1]
    /\ waiting = [a \in Attempts |-> FALSE]
    /\ done = [a \in Attempts |-> FALSE]
    /\ shipped = {}
    /\ sends = [a \in Attempts |-> [r \in Reqs |-> 0]]
    /\ rejectedSends = [a \in Attempts |-> [r \in Reqs |-> 0]]
    /\ badForward = FALSE
    /\ badGrant = FALSE
    /\ markOnClosed = FALSE
    /\ faults = 0

-----------------------------------------------------------------------------
(* Views *)

MarkIdx == 1 .. Len(marks)

\* The usage of the marks of `ms` that satisfy P, summed in one pass.
SumUsage(ms, P(_)) ==
    LET f[k \in 0 .. Len(ms)] == IF k = 0 THEN 0
                                 ELSE f[k - 1] + (IF P(k) THEN ms[k].usage ELSE 0)
    IN f[Len(ms)]

\* Marks the current gateway generation's journal holds.
Journal == {i \in MarkIdx : marks[i].gen = gGen}

\* Known usage of a slice in the gateway's journal: its Completed marks.
GKnown(a) ==
    LET P(i) == marks[i].gen = gGen /\ marks[i].att = a /\ marks[i].term = "completed"
    IN SumUsage(marks, P)
GUnknownInScope == \E i \in Journal : marks[i].term = "unknown"

\* Ground truth of the scope.
TruthSpent == LET P(i) == marks[i].term \notin {"inflight", "rejected"} IN SumUsage(marks, P)
KnownSpent == LET P(i) == marks[i].term = "completed" IN SumUsage(marks, P)
\* A mark whose usage kata cannot know: Unknown, lost before it was committed, or a
\* terminal a lost journal held that was never shipped.
TruthUnknownInScope ==
    \E i \in MarkIdx :
      \/ marks[i].term \in {"unknown", "lost_unjournaled"}
      \/ /\ marks[i].gen # gGen /\ marks[i].term # "rejected"
         /\ <<marks[i].gen, marks[i].seq>> \notin shipped

\* kata-control's freeze as it reads it, and as the durable truth has it.
UnclosedView(a) ==
    IF MUTANT = "unclosed_in_memory" THEN a \in unclosedMem ELSE cSlice[a] = "unclosed"
FrozenView ==
    \E a \in Attempts :
      \/ unknownAdopted[a] \/ cSlice[a] = "lost"
      \/ UnclosedView(a) /\ MUTANT # "refill_despite_unclosed"
FrozenTruth ==
    \E a \in Attempts :
      \/ unknownAdopted[a] \/ cSlice[a] \in {"unclosed", "lost"}
      \/ cSlice[a] \in {"open", "revoking"} /\ sliceGen[a] # gGen

-----------------------------------------------------------------------------
(* kata-control *)

\* A slice kata-control owes a SliceRevoke for is still open in this generation's
\* journal.
OwedRevokeOpen(a) ==
    \E b \in Attempts : b # a /\ cSlice[b] \in {"revoking", "unclosed"}
                      /\ sliceGen[b] = gGen /\ gSlice[b].open

\* The dispatch transaction grants and escrows a slice; the assignment goes out only
\* after the gateway journaled it. Ordered session: every SliceRevoke sent earlier on
\* it is processed first.
Grant(a) ==
    /\ cUp /\ gUp /\ link /\ cSlice[a] = "none"
    /\ \A b \in Attempts : ~revokePending[b]
    /\ BOUNDED => remaining > 0 /\ ~FrozenView
    /\ LET g == IF ~BOUNDED THEN NoGrant ELSE IF remaining < CHUNK THEN remaining ELSE CHUNK
       IN /\ grant' = [grant EXCEPT ![a] = g]
          /\ remaining' = IF BOUNDED THEN remaining - g ELSE remaining
          /\ gSlice' = [gSlice EXCEPT ![a] = [gen |-> gGen, open |-> TRUE, grant |-> g]]
    /\ cSlice' = [cSlice EXCEPT ![a] = "open"]
    /\ sliceGen' = [sliceGen EXCEPT ![a] = gGen]
    /\ badGrant' = (badGrant \/ OwedRevokeOpen(a))
    /\ UNCHANGED <<adopted, unknownAdopted, reported, verdict, charge, cUp, unclosedMem>>
    /\ UNCHANGED <<gUp, gGen, marks, gSeq>>
    /\ UNCHANGED <<session, harness, shipped, sends, rejectedSends, badForward, markOnClosed>>

\* A spent grant asks for a refill, drawn only from the undebited remainder and refused
\* while the scope is frozen.
Refill(a) ==
    /\ BOUNDED /\ cUp /\ gUp /\ link
    /\ cSlice[a] = "open" /\ gSlice[a].gen = gGen /\ gSlice[a].open
    /\ GKnown(a) >= gSlice[a].grant
    /\ IF MUTANT = "refill_ignores_remainder" THEN TRUE ELSE remaining > 0
    /\ ~FrozenView
    /\ LET g == IF MUTANT = "refill_ignores_remainder" THEN CHUNK
                ELSE IF remaining < CHUNK THEN remaining ELSE CHUNK
       IN /\ grant' = [grant EXCEPT ![a] = @ + g]
          /\ remaining' = remaining - g
          /\ gSlice' = [gSlice EXCEPT ![a].grant = @ + g]
    /\ UNCHANGED <<cSlice, sliceGen, adopted, unknownAdopted, reported, verdict, charge,
                   cUp, unclosedMem>>
    /\ UNCHANGED <<gUp, gGen, marks, gSeq>>
    /\ UNCHANGED <<session, harness, ghost>>

AdoptKey(m) == IF MUTANT = "adopt_by_seq_only" THEN <<0, m.seq>> ELSE <<m.gen, m.seq>>

\* The gateway ships one terminal; kata-control adopts it, idempotent by key.
Ship(i) ==
    /\ cUp /\ gUp /\ link
    /\ i \in Journal /\ marks[i].term \in {"completed", "unknown"}
    /\ <<marks[i].gen, marks[i].seq>> \notin shipped
    /\ shipped' = shipped \cup {<<marks[i].gen, marks[i].seq>>}
    /\ IF AdoptKey(marks[i]) \notin adopted
       THEN /\ adopted' = adopted \cup {AdoptKey(marks[i])}
            /\ unknownAdopted' = IF marks[i].term = "unknown"
                                 THEN [unknownAdopted EXCEPT ![marks[i].att] = TRUE]
                                 ELSE unknownAdopted
       ELSE UNCHANGED <<adopted, unknownAdopted>>
    /\ UNCHANGED <<remaining, grant, cSlice, sliceGen, reported, verdict, charge, cUp,
                   unclosedMem>>
    /\ UNCHANGED <<gw, session, harness, sends, rejectedSends, badForward, badGrant,
                   markOnClosed>>

\* Settlement starts: the node reported the turn's outcome, or went silent (LeaseOrder
\* owns when). SliceRevoke goes first, on the session if it is up, else at reconnect.
StartSettle(a, outcome) ==
    /\ cUp /\ cSlice[a] = "open"
    /\ outcome => done[a]
    /\ reported' = [reported EXCEPT ![a] = outcome]
    /\ cSlice' = [cSlice EXCEPT ![a] = "revoking"]
    /\ revokePending' = [revokePending EXCEPT ![a] = link]
    /\ UNCHANGED <<remaining, grant, sliceGen, adopted, unknownAdopted, verdict, charge,
                   cUp, unclosedMem>>
    /\ UNCHANGED <<gw, link, closedAnswer, harness, ghost>>

\* A lost slice's attempt settles with a reported outcome, else PROVEN AMBIGUOUS, at an
\* unknown charge: its marks are gone.
SettleLost(a, outcome) ==
    /\ cUp /\ cSlice[a] = "lost" /\ verdict[a] = "-"
    /\ outcome => done[a]
    /\ reported' = [reported EXCEPT ![a] = outcome]
    /\ verdict' = [verdict EXCEPT ![a] = IF outcome THEN "OUTCOME" ELSE "AMBIGUOUS"]
    /\ charge' = [charge EXCEPT ![a] = "unknown"]
    /\ UNCHANGED <<remaining, grant, cSlice, sliceGen, adopted, unknownAdopted, cUp,
                   unclosedMem>>
    /\ UNCHANGED <<gw, session, harness, ghost>>

\* ADR §5's verdict table for a closed slice.
ClosedVerdict(a, delivered) ==
    IF ~delivered THEN "NOT_PERFORMED"
    ELSE IF reported[a] THEN "OUTCOME" ELSE "AMBIGUOUS"

SliceMarks(a) == {i \in MarkIdx : marks[i].att = a /\ marks[i].gen = sliceGen[a]}

\* kata-control receives SliceClosed with every mark: it adopts them, credits unspent
\* grant (never for a slice holding an Unknown), and settles. A late SliceClosed (after
\* G) is evidence: the verdict given at G stands.
CtlClosed(a) ==
    /\ cUp /\ link /\ closedAnswer[a]
    /\ LET mine == SliceMarks(a)
           delivered == \E i \in mine : marks[i].delivered
           anyUnknown == \E i \in mine : marks[i].term = "unknown"
           completedUse == LET P(i) == i \in mine /\ marks[i].term = "completed"
                           IN SumUsage(marks, P)
       IN /\ adopted' = adopted \cup {AdoptKey(marks[i]) : i \in mine}
          /\ shipped' = shipped \cup {<<marks[i].gen, marks[i].seq>> : i \in mine}
          /\ unknownAdopted' = [unknownAdopted EXCEPT ![a] = @ \/ anyUnknown]
          /\ remaining' = IF BOUNDED /\ ~anyUnknown /\ completedUse < grant[a]
                          THEN remaining + (grant[a] - completedUse) ELSE remaining
          /\ IF cSlice[a] = "unclosed"
             THEN UNCHANGED <<verdict, charge>>
             ELSE /\ verdict' = [verdict EXCEPT ![a] = ClosedVerdict(a, delivered)]
                  /\ charge' = [charge EXCEPT ![a] =
                                  IF (IF MUTANT = "charge_from_adopted"
                                      THEN unknownAdopted[a] ELSE anyUnknown)
                                  THEN "unknown" ELSE "exact"]
    /\ cSlice' = [cSlice EXCEPT ![a] = "closed"]
    /\ closedAnswer' = [closedAnswer EXCEPT ![a] = FALSE]
    /\ unclosedMem' = unclosedMem \ {a}
    /\ UNCHANGED <<grant, sliceGen, reported, cUp>>
    /\ UNCHANGED <<gw, link, revokePending, harness, sends, rejectedSends, badForward,
                   badGrant, markOnClosed>>

\* G passes without SliceClosed: a reported outcome is kept at an unknown charge,
\* otherwise PROVEN AMBIGUOUS; the slice is unclosed and freezes its scope.
SliceTimeout(a) ==
    /\ cUp /\ cSlice[a] = "revoking"
    /\ cSlice' = [cSlice EXCEPT ![a] = "unclosed"]
    /\ unclosedMem' = unclosedMem \cup {a}
    /\ verdict' = [verdict EXCEPT ![a] =
                     IF reported[a] /\ MUTANT # "past_g_drops_outcome" THEN "OUTCOME" ELSE "AMBIGUOUS"]
    /\ charge' = [charge EXCEPT ![a] = "unknown"]
    /\ UNCHANGED <<remaining, grant, sliceGen, adopted, unknownAdopted, reported, cUp>>
    /\ UNCHANGED <<gw, session, harness, ghost>>

\* The mutant: the verdict read from the marks shipped so far, without SliceClosed.
SettleWithoutClose(a) ==
    /\ MUTANT = "settle_before_slice_close"
    /\ cUp /\ cSlice[a] = "revoking"
    /\ LET delivered == \E i \in MarkIdx :
                           /\ marks[i].att = a /\ marks[i].delivered
                           /\ <<marks[i].gen, marks[i].seq>> \in shipped
       IN verdict' = [verdict EXCEPT ![a] = ClosedVerdict(a, delivered)]
    /\ cSlice' = [cSlice EXCEPT ![a] = "closed"]
    /\ charge' = [charge EXCEPT ![a] = "exact"]
    /\ UNCHANGED <<remaining, grant, sliceGen, adopted, unknownAdopted, reported, cUp,
                   unclosedMem>>
    /\ UNCHANGED <<gw, session, harness, ghost>>

-----------------------------------------------------------------------------
(* Gateway *)

\* The harness's request `a` failed: with its retry layer it re-sends the same logical
\* request, otherwise it moves on to the next (the turn ends after the last).
AfterFailure(a, retry) ==
    /\ next' = [next EXCEPT ![a] = IF retry THEN @ ELSE @ + 1]
    /\ done' = [done EXCEPT ![a] = @ \/ (~retry /\ next[a] = MaxReq)]

\* The gateway processes SliceRevoke: it stops admitting marks on the slice, cuts its
\* open streams (Unknown{cut}), and answers SliceClosed with every mark. A repeated
\* SliceRevoke is answered again. The turn goes on: what it sends next is refused.
GwRevoke(a) ==
    /\ gUp /\ link /\ revokePending[a] /\ sliceGen[a] = gGen
    /\ \E cutDelivered \in BOOLEAN, cutUsage \in 0 .. UMAX :
         marks' = [i \in MarkIdx |->
                     IF marks[i].att = a /\ marks[i].gen = gGen /\ marks[i].term = "inflight"
                     THEN [marks[i] EXCEPT !.term = "unknown", !.delivered = @ \/ cutDelivered,
                                           !.usage = cutUsage]
                     ELSE marks[i]]
    /\ gSlice' = [gSlice EXCEPT ![a].open = FALSE]
    /\ revokePending' = [revokePending EXCEPT ![a] = FALSE]
    /\ closedAnswer' = [closedAnswer EXCEPT ![a] = TRUE]
    /\ waiting' = [waiting EXCEPT ![a] = FALSE]
    /\ IF waiting[a] THEN AfterFailure(a, HARNESS_RETRIES) ELSE UNCHANGED <<next, done>>
    /\ UNCHANGED <<ctl, gUp, gGen, gSeq, link, ghost>>

\* The checks of ADR §5's table this model reaches: an open slice of this generation,
\* a grant not spent by known usage, no Unknown mark in the scope.
Admissible(a) ==
    /\ gUp
    /\ gSlice[a].gen = gGen /\ (gSlice[a].open \/ MUTANT = "admit_on_closed_slice")
    /\ BOUNDED => GKnown(a) < gSlice[a].grant
    /\ BOUNDED /\ MUTANT # "no_unknown_freeze" => ~GUnknownInScope

\* ADR §5's claim, read on ground truth: "no request is forwarded in a bounded scope
\* once its grants are spent by known usage or any mark in it is Unknown, except on an
\* unclosed slice within its escrowed grant".
ClaimViolated(a) ==
    /\ BOUNDED
    /\ KnownSpent >= B \/ TruthUnknownInScope
    /\ cSlice[a] # "unclosed"

\* After the upstream connection is ready and before the first upstream byte the
\* gateway checks the request, commits its mark (one transaction and fsync) and
\* forwards. The node reaches the gateway whatever the control session does.
Forward(a) ==
    /\ ~done[a] /\ ~waiting[a] /\ next[a] <= MaxReq
    /\ Len(marks) < MaxMarks
    /\ Admissible(a)
    /\ marks' = Append(marks, [att |-> a, req |-> next[a], gen |-> gGen, seq |-> gSeq,
                               term |-> "inflight", delivered |-> FALSE, usage |-> 0,
                               journaled |-> MUTANT # "mark_after_first_byte"])
    /\ sends' = [sends EXCEPT ![a][next[a]] = @ + 1]
    /\ gSeq' = gSeq + 1
    /\ waiting' = [waiting EXCEPT ![a] = TRUE]
    /\ badForward' = (badForward \/ ClaimViolated(a))
    /\ markOnClosed' = (markOnClosed \/ cSlice[a] \in {"closed", "lost"})
    /\ UNCHANGED <<ctl, gUp, gGen, gSlice, session, next, done, shipped, rejectedSends,
                   badGrant>>

\* The mutant's mark is committed after forwarding began.
JournalLate(i) ==
    /\ MUTANT = "mark_after_first_byte" /\ gUp
    /\ i \in Journal /\ ~marks[i].journaled /\ marks[i].term = "inflight"
    /\ marks' = [marks EXCEPT ![i].journaled = TRUE]
    /\ UNCHANGED <<ctl, gUp, gGen, gSlice, gSeq, session, harness, ghost>>

\* Upstream answers an in-flight mark: Completed{usage} (output delivered); Rejected (a
\* status promising no processing: re-sent, by the gateway on a 401 or by the
\* harness); Unknown{delivered = false} (a transient failure before any output, which
\* promises nothing); Unknown{delivered = true} (cut after output).
Upstream(i) ==
    /\ gUp /\ i \in Journal /\ marks[i].term = "inflight" /\ marks[i].journaled
    /\ \E outcome \in {"completed", "rejected", "unknown_pre", "unknown_cut"},
          u \in 0 .. UMAX :
         /\ outcome = "completed" => u >= 1
         /\ outcome = "rejected" => u = 0
         /\ LET a == marks[i].att
                r == marks[i].req
                retry == \/ outcome = "rejected"
                         \/ /\ outcome = "unknown_pre"
                            /\ HARNESS_RETRIES \/ MUTANT = "gateway_reissues_unknown"
            IN /\ marks' = [marks EXCEPT
                              ![i].term = CASE outcome = "completed" -> "completed"
                                            [] outcome = "rejected" -> "rejected"
                                            [] OTHER -> "unknown",
                              ![i].delivered = outcome \in {"completed", "unknown_cut"},
                              ![i].usage = u]
               /\ rejectedSends' = IF outcome = "rejected"
                                   THEN [rejectedSends EXCEPT ![a][r] = @ + 1]
                                   ELSE rejectedSends
               /\ waiting' = [waiting EXCEPT ![a] = FALSE]
               /\ next' = IF retry THEN next ELSE [next EXCEPT ![a] = @ + 1]
               /\ done' = IF ~retry /\ next[a] = MaxReq THEN [done EXCEPT ![a] = TRUE]
                          ELSE done
    /\ UNCHANGED <<ctl, gUp, gGen, gSlice, gSeq, session, shipped, sends, badForward,
                   badGrant, markOnClosed>>

\* The turn ends early (an error, a stop).
HarnessEnd(a) ==
    /\ ~done[a] /\ ~waiting[a]
    /\ done' = [done EXCEPT ![a] = TRUE]
    /\ UNCHANGED <<ctl, gw, session, next, waiting, ghost>>

-----------------------------------------------------------------------------
(* Faults *)

\* A gateway restart keeps its journal: open marks become Unknown{gateway_lost,
\* delivered = true}; slices survive. Under the mutant a mark not yet committed is
\* gone though its request was forwarded. Each harness sees its stream fail before a
\* response reached it (the conservative `delivered` is the gateway's, not the
\* harness's view), and its retry layer re-sends.
GwCrash ==
    /\ ALLOW_GW_CRASH /\ gUp
    /\ \E u \in 0 .. UMAX :
         marks' = [i \in MarkIdx |->
                     IF marks[i].gen = gGen /\ marks[i].term = "inflight"
                     THEN IF marks[i].journaled
                          THEN [marks[i] EXCEPT !.term = "unknown", !.delivered = TRUE,
                                                !.usage = u]
                          ELSE [marks[i] EXCEPT !.term = "lost_unjournaled", !.usage = u]
                     ELSE marks[i]]
    /\ waiting' = [a \in Attempts |-> FALSE]
    /\ next' = [a \in Attempts |-> IF waiting[a] /\ ~HARNESS_RETRIES THEN next[a] + 1
                                   ELSE next[a]]
    /\ done' = [a \in Attempts |->
                  done[a] \/ (waiting[a] /\ ~HARNESS_RETRIES /\ next[a] = MaxReq)]
    /\ gUp' = FALSE
    /\ link' = FALSE
    /\ revokePending' = [a \in Attempts |-> FALSE]
    /\ closedAnswer' = [a \in Attempts |-> FALSE]
    /\ UNCHANGED <<ctl, gGen, gSlice, gSeq, ghost>>

\* The gateway's data directory is lost while it is down: a new generation.
GwLoseData ==
    /\ ALLOW_GW_LOSS /\ ~gUp
    /\ gGen' = gGen + 1
    /\ gSeq' = 1
    /\ gSlice' = [a \in Attempts |-> [gen |-> 0, open |-> FALSE, grant |-> 0]]
    /\ UNCHANGED <<ctl, gUp, marks, session, harness, ghost>>

GwBoot ==
    /\ ~gUp
    /\ gUp' = TRUE
    /\ UNCHANGED <<ctl, gGen, gSlice, marks, gSeq, session, harness, ghost>>

LinkDown ==
    /\ ALLOW_LINK_LOSS /\ link
    /\ link' = FALSE
    /\ revokePending' = [a \in Attempts |-> FALSE]
    /\ closedAnswer' = [a \in Attempts |-> FALSE]
    /\ UNCHANGED <<ctl, gw, harness, ghost>>

\* The session comes back. kata-control first reads the gateway's generation: every
\* slice an older generation journaled and did not close is lost. Then it resends
\* SliceRevoke for every revoking or unclosed slice, ahead of anything else.
LinkUp ==
    /\ ~link /\ cUp /\ gUp
    /\ link' = TRUE
    /\ LET lostNow(a) == /\ MUTANT # "ignore_gateway_generation"
                         /\ cSlice[a] \in {"open", "revoking", "unclosed"}
                         /\ sliceGen[a] # gGen
           resend(a) == /\ cSlice[a] \in {"revoking", "unclosed"} /\ sliceGen[a] = gGen
                        /\ MUTANT # "no_slice_revoke_resend"
       IN /\ cSlice' = [a \in Attempts |-> IF lostNow(a) THEN "lost" ELSE cSlice[a]]
          /\ verdict' = [a \in Attempts |->
                           IF lostNow(a) /\ cSlice[a] = "revoking"
                           THEN IF reported[a] THEN "OUTCOME" ELSE "AMBIGUOUS"
                           ELSE verdict[a]]
          /\ charge' = [a \in Attempts |->
                          IF lostNow(a) /\ cSlice[a] = "revoking" THEN "unknown" ELSE charge[a]]
          /\ revokePending' = [a \in Attempts |-> resend(a)]
    /\ UNCHANGED <<remaining, grant, sliceGen, adopted, unknownAdopted, reported, cUp,
                   unclosedMem>>
    /\ UNCHANGED <<gw, closedAnswer, harness, ghost>>

\* kata-control restarts: its rows are durable; the session and its memory are not.
CtlCrash ==
    /\ ALLOW_CTL_CRASH /\ cUp
    /\ cUp' = FALSE
    /\ link' = FALSE
    /\ unclosedMem' = {}
    /\ revokePending' = [a \in Attempts |-> FALSE]
    /\ closedAnswer' = [a \in Attempts |-> FALSE]
    /\ UNCHANGED <<remaining, grant, cSlice, sliceGen, adopted, unknownAdopted, reported,
                   verdict, charge>>
    /\ UNCHANGED <<gw, harness, ghost>>

CtlBoot ==
    /\ ~cUp
    /\ cUp' = TRUE
    /\ UNCHANGED <<remaining, grant, cSlice, sliceGen, adopted, unknownAdopted, reported,
                   verdict, charge, unclosedMem>>
    /\ UNCHANGED <<gw, session, harness, ghost>>

-----------------------------------------------------------------------------

Fault == GwCrash \/ GwLoseData \/ LinkDown \/ CtlCrash

Step ==
    \/ \E a \in Attempts :
         \/ Grant(a) \/ Refill(a) \/ Forward(a) \/ HarnessEnd(a)
         \/ StartSettle(a, TRUE) \/ StartSettle(a, FALSE)
         \/ SettleLost(a, TRUE) \/ SettleLost(a, FALSE)
         \/ GwRevoke(a) \/ CtlClosed(a) \/ SliceTimeout(a) \/ SettleWithoutClose(a)
    \/ \E i \in MarkIdx : Ship(i) \/ Upstream(i) \/ JournalLate(i)
    \/ GwBoot \/ LinkUp \/ CtlBoot

Next ==
    \/ faults < MaxFaults /\ Fault /\ faults' = faults + 1
    \/ Step /\ UNCHANGED faults

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Invariants *)

\* ADR §5's bound claim, exactly as stated, read on ground truth.
NoForwardPastTheBound == ~badForward

\* Ground truth: upstream processed at most the bound plus one overshooting request per
\* slice crossing (what per-slice escrow gives).
SpendWithinBoundPlusInFlight ==
    BOUNDED => TruthSpent <= B + UMAX * Cardinality(Attempts)

\* ADR §5: no refill or new slice in a scope holding an unclosed or lost slice or an
\* adopted Unknown, read on kata-control's durable truth.
NoRefillWhenFrozen ==
    [][BOUNDED /\ FrozenTruth =>
         /\ \A a \in Attempts : grant'[a] = grant[a]
         /\ remaining' >= remaining]_vars

\* ADR §1 and §5: a model request is never re-issued; only a request that ended
\* Rejected (promised not processed) is sent again.
NoReissue ==
    \A a \in Attempts : \A r \in Reqs : sends[a][r] <= 1 + rejectedSends[a][r]

\* No request reaches upstream without a committed mark.
NoForwardWithoutMark == \A i \in MarkIdx : marks[i].term # "lost_unjournaled"

\* NOT PERFORMED only from a closed slice no mark of which delivered output, ever.
NotPerformedIsSound ==
    \A a \in Attempts :
      verdict[a] = "NOT_PERFORMED" =>
        /\ cSlice[a] = "closed"
        /\ ~\E i \in MarkIdx : marks[i].att = a /\ marks[i].delivered

\* Past G or after a lost journal: AMBIGUOUS only for an attempt with no reported outcome.
PastGAmbiguousOnlyUnreported ==
    \A a \in Attempts :
      (verdict[a] = "AMBIGUOUS" /\ cSlice[a] \in {"unclosed", "lost"}) => ~reported[a]

\* The charge is never exact (never zero for it) when a mark of the attempt may have
\* been processed unseen.
ChargeNeverZeroForUnknown ==
    \A a \in Attempts :
      charge[a] = "exact" =>
        ~\E i \in MarkIdx : marks[i].att = a /\ marks[i].term \in {"unknown", "lost_unjournaled"}

\* Adoption is idempotent by (generation, sequence) and loses nothing: a shipped Unknown
\* terminal reaches kata-control's freeze.
AdoptionComplete ==
    \A i \in MarkIdx :
      (<<marks[i].gen, marks[i].seq>> \in shipped /\ marks[i].term = "unknown")
        => unknownAdopted[marks[i].att]

\* ADR §5: SliceRevoke is resent first on every connection, so no new slice is
\* journaled while a slice kata-control owes a SliceRevoke for is open.
NewSliceAfterOwedRevokes == ~badGrant

\* Plan M0: no mark on a closed slice. Read on kata-control's records: once it holds a
\* slice's SliceClosed, or holds the slice lost with its journal's generation, no mark
\* of the slice is journaled (the turn goes on asking; the gateway's check refuses it).
\* An unclosed slice is ADR §5's stated exception.
NoMarkOnClosedSlice == ~markOnClosed

=============================================================================
