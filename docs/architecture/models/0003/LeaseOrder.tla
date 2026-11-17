----------------------------- MODULE LeaseOrder -----------------------------
(***************************************************************************)
(* ADR 0003 §4 (node session) and the settlement half of §5 as a checked   *)
(* model: one stage's retry chain of attempts dispatched to nodes that     *)
(* renew a node-wide lease on their own CLOCK_BOOTTIME, a provider per     *)
(* capsule that kills it at the lease deadline D without the node's help,  *)
(* a live node that answers a dead provider with kill_and_contain, and a   *)
(* control plane that keeps no lease state on disk and settles a silent    *)
(* node's attempts only after W = L(1+rho) + K + slack on its own clock,   *)
(* counted from t_recv of the last granted renewal, or from boot.          *)
(*                                                                         *)
(* TIME is relative, so the check covers unbounded time: every clock fact  *)
(* is a countdown to a deadline or an age capped where it stops mattering, *)
(* and Tick moves them all one real unit. A clock with per-clock drift     *)
(* rho = RHO_NUM / RHO_DEN against real time measures a duration d after a *)
(* real duration in [d / (1 + rho), d / (1 - rho)]; the model widens that  *)
(* to integers (floor below, ceiling above), which only adds behaviours:   *)
(* a property that holds here holds for the exact interval. The node's D   *)
(* is t_send + L on the node's clock, which the provider reads too: the    *)
(* provider may cross D from LeaseRealMin after t_send and has crossed it  *)
(* by LeaseRealMax, and must have emptied the capsule K after that.        *)
(* kata-control's W cannot have elapsed before SettleRealMin real units.   *)
(*                                                                         *)
(* An obligation ("must happen within d") blocks Tick: time cannot pass    *)
(* its deadline while it is open.                                          *)
(*                                                                         *)
(* NAMED ADVERSARY STEPS (ADR 0003 §4, plan M0): the double fault (a dead  *)
(* provider under a stalled node) and a suspend. A capsule that lived      *)
(* through one is `excused`: the order invariant is stated outside them,   *)
(* as the ADR states it. EXCUSE_CRASHED = TRUE also excuses a dead         *)
(* provider under a crashed node, which the ADR does not name (finding F7).*)
(*                                                                         *)
(* The gateway keeps its own journal and revocation mirror: it closes a    *)
(* slice when it processes SliceRevoke, and learns a revocation over its   *)
(* session with kata-control, after the commit (ADR §3).                   *)
(*                                                                         *)
(* MUTANT selects one deliberate defect for the RED half; the real model   *)
(* runs MUTANT = "none". Each mutant removes one ADR mechanism.            *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    Nodes,            \* execution nodes
    MaxAttempts,      \* length of the stage's retry chain
    MaxInc,           \* incarnations per node (model-checking bound)
    L,                \* lease length, node clock units
    K,                \* ADR's K: the provider crossing D to an empty subtree, real units
    K_CONTAIN,        \* a live node's kill_and_contain: provider death to empty subtree
    SLACK,            \* control clock units
    RHO_NUM, RHO_DEN, \* per-clock drift bound against real time
    T_RENEW,          \* renewal period (liveness only: any period is checked)
    G_WAIT,           \* G: kata-control's wait for SliceClosed, real units
    HARNESS_IN_NODE,  \* TRUE before S4: the embedded loop runs in kata-node
    Kinds,            \* the attempt kinds dispatched: "shell", "embedded"
    ALLOW_STALL, ALLOW_CRASH, ALLOW_PROVIDER_DEATH, ALLOW_CONTROL_RESTART,
    ALLOW_REVOKE, ALLOW_GATEWAY_DOWN, ALLOW_NODE_WIPE, ALLOW_SUSPEND,
    ALLOW_PARTITION,
    MaxFaults,        \* adversary events per behaviour
    EXCUSE_CRASHED,   \* TRUE: a dead provider under a CRASHED node is a named step too
    MUTANT

Mutants == {"none",
            "kill_on_node_process",     \* the kill waits on the node process's own loop
            "settle_at_revoke",         \* revocation settles at once (ADR §3 forbids)
            "no_boot_wait",             \* a restarted control plane settles at boot
            "lost_frame_not_performed", \* a fact the restart lost read as "no frame"
            "settle_before_slice_close",\* marks judged without SliceClosed
            "hello_without_sweep",      \* Hello before the subtree is confirmed empty
            "trust_wiped_intake",       \* a new node generation judged by its empty journal
            "start_before_intake",      \* container created before `Started` is fsynced
            "redeliver_after_hello",    \* an open attempt re-sent to the new incarnation
            "past_g_drops_outcome",     \* past G every mark-judged attempt AMBIGUOUS
            "result_after_settlement",  \* a result frame folds into a settled attempt
            "no_slack",                 \* W = L(1+rho) + K, no slack
            "w_without_rho",            \* W = L + K + slack: the drift term dropped
            "mark_on_closed_slice",     \* the mark check skips "the slice is open"
            "mark_despite_revocation"}  \* the mark check skips "the node is not revoked"

ASSUME MUTANT \in Mutants
ASSUME RHO_NUM >= 0 /\ RHO_DEN > RHO_NUM
ASSUME Kinds \subseteq {"shell", "embedded"} /\ Kinds # {}

NoNode == "none"
Attempts == 1 .. MaxAttempts

CeilDiv(a, b) == (a + b - 1) \div b
Min(a, b) == IF a < b THEN a ELSE b
Max(a, b) == IF a > b THEN a ELSE b
Down(x) == IF x > 0 THEN x - 1 ELSE x        \* a countdown; -1 (none) and 0 stay

\* Real duration of L node-clock units, widened.
LeaseRealMin == (L * RHO_DEN) \div (RHO_DEN + RHO_NUM)
LeaseRealMax == CeilDiv(L * RHO_DEN, RHO_DEN - RHO_NUM)
\* W in control-clock units, as ADR §4 writes it, and the earliest real time it ends.
EffSlack == IF MUTANT = "no_slack" THEN 0 ELSE SLACK
SettleWait == IF MUTANT = "w_without_rho" THEN L + K + EffSlack
              ELSE CeilDiv(L * (RHO_DEN + RHO_NUM), RHO_DEN) + K + EffSlack
SettleRealMin == (SettleWait * RHO_DEN) \div (RHO_DEN + RHO_NUM)

Verdicts == {"-", "NOT_PERFORMED", "OUTCOME", "AMBIGUOUS"}

VARIABLES
    \* ---- node ----
    nSt,        \* "up" | "stalled" | "down" | "suspended"
    nInc,       \* incarnation the node holds; 0 = none (kill, sweep, Hello)
    nGen,       \* the node's data generation (a replaced data directory mints a new one)
    nLo, nHi,   \* countdowns to the node clock possibly / surely past its D (-1: no lease)
    renewAge,   \* time since the node's last renewal, capped at T_RENEW
    intake,     \* fsynced intake journal: [Nodes -> [Attempts -> "none"|"accepted"|"started"]]
    \* ---- capsule: one per attempt (`deliveries` counts any second one) ----
    cap,
    turn,       \* the node-resident harness's turn for the attempt is alive (before S4)
    \* ---- control plane ----
    cUp,
    silent,     \* in memory: time since the node's last granted renewal, or since boot
    cSess,      \* in memory: an authenticated session with the node is open
    cInc,       \* durable: incarnation welcomed
    cNGen,      \* durable: node generation recorded at Hello
    cLapsed,    \* durable: incarnations whose attempts were settled silent
    revoked,    \* durable
    att,        \* durable attempt rows
    frame,      \* in memory: "no" | "yes" | "unknown": was the dispatch frame written
    reported,   \* the node reported the attempt's outcome
    \* ---- gateway, abstracted to what settlement reads ----
    gwUp,
    slice,      \* kata-control's: "none" | "open" | "closed" | "unclosed"
    revokeAge,  \* time since SliceRevoke, capped at G_WAIT (-1: not sent)
    delivered,  \* some mark of the slice delivered model output toward the node
    gwOpen,     \* the gateway's journal holds the slice open (admits marks)
    gwRevoked,  \* the gateway's revocation mirror
    \* ---- network: renewals and grants carry their age since t_send ----
    msgs,
    \* ---- ghosts ----
    started, deliveries, faults,
    badMark,          \* a mark on a slice kata-control holds closed, or for a node the
                      \* gateway's mirror holds revoked
    markAfterRevoke   \* a mark for a node after kata-control committed its revocation

\* The gateway's slice journal and revocation mirror, and the ghosts on its marks.
egress == <<gwOpen, gwRevoked, badMark, markAfterRevoke>>

vars == <<nSt, nInc, nGen, nLo, nHi, renewAge, intake, cap, turn, cUp, silent, cSess,
          cInc, cNGen, cLapsed, revoked, att, frame, reported, gwUp, slice, revokeAge,
          delivered, msgs, started, deliveries, faults, egress>>

\* Nodes are interchangeable: a check may reduce by permuting them.
Symmetry == Permutations(Nodes)

NoCap == [run |-> FALSE, node |-> NoNode, prov |-> FALSE, lo |-> -1, kill |-> -1,
          contain |-> -1, exited |-> FALSE, excused |-> FALSE]
NoAtt == [st |-> "none", node |-> NoNode, inc |-> 0, kind |-> "shell", verdict |-> "-",
          ev |-> "-"]

Init ==
    /\ nSt = [n \in Nodes |-> "up"]
    /\ nInc = [n \in Nodes |-> 0]
    /\ nGen = [n \in Nodes |-> 1]
    /\ nLo = [n \in Nodes |-> -1]
    /\ nHi = [n \in Nodes |-> -1]
    /\ renewAge = [n \in Nodes |-> 0]
    /\ intake = [n \in Nodes |-> [a \in Attempts |-> "none"]]
    /\ cap = [a \in Attempts |-> NoCap]
    /\ turn = [a \in Attempts |-> FALSE]
    /\ cUp = TRUE
    /\ silent = [n \in Nodes |-> 0]
    /\ cSess = [n \in Nodes |-> FALSE]
    /\ cInc = [n \in Nodes |-> 0]
    /\ cNGen = [n \in Nodes |-> 0]
    /\ cLapsed = [n \in Nodes |-> {}]
    /\ revoked = [n \in Nodes |-> FALSE]
    /\ att = [a \in Attempts |-> NoAtt]
    /\ frame = [a \in Attempts |-> "no"]
    /\ reported = [a \in Attempts |-> FALSE]
    /\ gwUp = TRUE
    /\ slice = [a \in Attempts |-> "none"]
    /\ revokeAge = [a \in Attempts |-> -1]
    /\ delivered = [a \in Attempts |-> FALSE]
    /\ msgs = {}
    /\ started = [a \in Attempts |-> FALSE]
    /\ deliveries = [a \in Attempts |-> 0]
    /\ faults = 0
    /\ gwOpen = [a \in Attempts |-> FALSE]
    /\ gwRevoked = [n \in Nodes |-> FALSE]
    /\ badMark = FALSE
    /\ markAfterRevoke = FALSE

-----------------------------------------------------------------------------
(* Settlement helpers *)

OnNode(a, n) == cap[a].run /\ cap[a].node = n

\* What kata-control's own records say about a dispatch, for a silent node or a new
\* node generation: no frame written is NOT PERFORMED; anything else, a fact a restart
\* lost included, may have run.
FrameEvidence(a) ==
    IF frame[a] = "no" \/ (MUTANT = "lost_frame_not_performed" /\ frame[a] = "unknown")
    THEN "not_performed" ELSE "possible"

IntakeEvidence(n, a) ==
    IF intake[n][a] = "started" THEN "possible" ELSE "not_performed"

\* Settle every open attempt of node n by its evidence `Ev(a)`. A shell attempt settles
\* at once; an embedded-harness one, for any reason, only once its slice closes
\* (SliceRevoke first), carrying its evidence to that point.
SettleOpen(n, Ev(_)) ==
    LET open == {a \in Attempts : att[a].st = "dispatched" /\ att[a].node = n}
    IN /\ att' = [a \in Attempts |->
                    IF a \in open
                    THEN LET e == Ev(a) IN
                         IF att[a].kind = "embedded"
                         THEN [att[a] EXCEPT !.st = "settling", !.ev = e]
                         ELSE IF e = "not_performed"
                              THEN [att[a] EXCEPT !.st = "settled", !.verdict = "NOT_PERFORMED"]
                              ELSE [att[a] EXCEPT !.st = "settled",
                                       !.verdict = IF reported[a] THEN "OUTCOME" ELSE "AMBIGUOUS"]
                    ELSE att[a]]
       /\ revokeAge' = [a \in Attempts |->
                          IF a \in open /\ att[a].kind = "embedded" THEN 0 ELSE revokeAge[a]]

\* ADR §5's table for a closed slice.
MarkVerdict(a) ==
    IF ~delivered[a] THEN "NOT_PERFORMED"
    ELSE IF reported[a] THEN "OUTCOME" ELSE "AMBIGUOUS"

\* Past G: an attempt judged by intake or by kata-control's records keeps that verdict;
\* one marks must judge keeps a reported outcome, else PROVEN AMBIGUOUS.
TimeoutVerdict(a) ==
    IF att[a].ev = "not_performed" THEN "NOT_PERFORMED"
    ELSE IF reported[a] /\ MUTANT # "past_g_drops_outcome" THEN "OUTCOME" ELSE "AMBIGUOUS"

-----------------------------------------------------------------------------
(* Time *)

ProviderKillDue(a) ==
    /\ cap[a].run /\ cap[a].prov
    /\ IF MUTANT = "kill_on_node_process"
       THEN nSt[cap[a].node] = "up"
       ELSE nSt[cap[a].node] # "suspended"
ContainDue(a) ==
    cap[a].run /\ ~cap[a].prov /\ nSt[cap[a].node] = "up"

Tick ==
    /\ \A a \in Attempts :
         /\ ProviderKillDue(a) => cap[a].kill > 0
         /\ ContainDue(a) => cap[a].contain > 0
    /\ nLo' = [n \in Nodes |-> Down(nLo[n])]
    /\ nHi' = [n \in Nodes |-> Down(nHi[n])]
    /\ renewAge' = [n \in Nodes |-> Min(renewAge[n] + 1, T_RENEW)]
    /\ cap' = [a \in Attempts |->
                 IF ~cap[a].run THEN cap[a]
                 ELSE [cap[a] EXCEPT !.lo = Down(@), !.kill = Down(@), !.contain = Down(@)]]
    /\ silent' = [n \in Nodes |-> Min(silent[n] + 1, SettleRealMin)]
    /\ revokeAge' = [a \in Attempts |->
                       IF revokeAge[a] = -1 THEN -1 ELSE Min(revokeAge[a] + 1, G_WAIT)]
    /\ msgs' = {IF m.type \in {"renew", "grant"}
                THEN [m EXCEPT !.age = Min(@ + 1, LeaseRealMax)] ELSE m : m \in msgs}
    /\ UNCHANGED <<nSt, nInc, nGen, intake, turn, cUp, cSess, cInc, cNGen, cLapsed, revoked,
                   att, frame, reported, gwUp, slice, delivered, started, deliveries,
                   egress>>

-----------------------------------------------------------------------------
(* Node *)

\* A node with no incarnation empties its kata cgroup subtree (confirmed from outside).
NodeSweep(n) ==
    /\ nSt[n] = "up" /\ nInc[n] = 0
    /\ \E a \in Attempts : OnNode(a, n) \/ (turn[a] /\ cap[a].node = n)
    /\ cap' = [a \in Attempts |-> IF OnNode(a, n) THEN [cap[a] EXCEPT !.run = FALSE] ELSE cap[a]]
    /\ turn' = [a \in Attempts |-> IF cap[a].node = n THEN FALSE ELSE turn[a]]
    /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, renewAge, intake, cUp, silent, cSess, cInc,
                   cNGen, cLapsed, revoked, att, frame, reported, gwUp, slice, revokeAge,
                   delivered, msgs, started, deliveries, egress>>

\* Hello opens a new incarnation; an atomic exchange: kata-control commits the
\* incarnation and the settlement of the node's earlier attempts, then Welcome.
\* Hello is the incarnation's first lease request (t_send = t_recv).
NodeHello(n) ==
    /\ nSt[n] = "up" /\ nInc[n] = 0 /\ cUp /\ ~revoked[n]
    /\ cInc[n] < MaxInc
    /\ MUTANT # "hello_without_sweep" =>
         \A a \in Attempts : ~OnNode(a, n) /\ ~(turn[a] /\ cap[a].node = n)
    /\ LET i == cInc[n] + 1
           newGen == nGen[n] # cNGen[n] /\ cNGen[n] # 0
           Ev(a) == IF newGen /\ MUTANT # "trust_wiped_intake"
                    THEN FrameEvidence(a) ELSE IntakeEvidence(n, a)
       IN /\ cInc' = [cInc EXCEPT ![n] = i]
          /\ nInc' = [nInc EXCEPT ![n] = i]
          /\ IF MUTANT = "redeliver_after_hello"
             THEN /\ att' = [a \in Attempts |->
                               IF att[a].st = "dispatched" /\ att[a].node = n
                               THEN [att[a] EXCEPT !.inc = i] ELSE att[a]]
                  /\ frame' = [a \in Attempts |->
                                 IF att[a].st = "dispatched" /\ att[a].node = n
                                 THEN "no" ELSE frame[a]]
                  /\ UNCHANGED revokeAge
             ELSE /\ SettleOpen(n, Ev)
                  /\ UNCHANGED frame
    /\ cNGen' = [cNGen EXCEPT ![n] = nGen[n]]
    /\ cSess' = [cSess EXCEPT ![n] = TRUE]
    /\ silent' = [silent EXCEPT ![n] = 0]
    /\ nLo' = [nLo EXCEPT ![n] = LeaseRealMin]
    /\ nHi' = [nHi EXCEPT ![n] = LeaseRealMax]
    /\ renewAge' = [renewAge EXCEPT ![n] = 0]
    /\ intake' = [intake EXCEPT ![n] = [a \in Attempts |-> "none"]]
    \* Frames of the earlier incarnation are fenced by it; dropping them is equivalent.
    /\ msgs' = {m \in msgs : m.n # n}
    /\ UNCHANGED <<nSt, nGen, cap, turn, cUp, cLapsed, revoked, reported, gwUp, slice,
                   delivered, started, deliveries, egress>>

\* The node's clock may have passed D: it drops the incarnation (kill, sweep, Hello).
NodeLeaseLapse(n) ==
    /\ nSt[n] = "up" /\ nInc[n] # 0 /\ nLo[n] = 0
    /\ nInc' = [nInc EXCEPT ![n] = 0]
    /\ UNCHANGED <<nSt, nGen, nLo, nHi, renewAge, intake, cap, turn, cUp, silent, cSess,
                   cInc, cNGen, cLapsed, revoked, att, frame, reported, gwUp, slice,
                   revokeAge, delivered, msgs, started, deliveries, egress>>

NodeRenew(n) ==
    /\ nSt[n] = "up" /\ nInc[n] # 0
    /\ renewAge[n] >= T_RENEW
    /\ ~\E m \in msgs : m.type = "renew" /\ m.n = n
    /\ msgs' = msgs \cup {[type |-> "renew", n |-> n, inc |-> nInc[n], age |-> 0, a |-> 0]}
    /\ renewAge' = [renewAge EXCEPT ![n] = 0]
    /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, intake, cap, turn, cUp, silent, cSess, cInc,
                   cNGen, cLapsed, revoked, att, frame, reported, gwUp, slice, revokeAge,
                   delivered, started, deliveries, egress>>

\* A grant moves D to t_send + L; the node forwards LeaseUntil{D} to the provider of
\* every running capsule. D only moves forward.
NodeRecvGrant(n) ==
    \E m \in msgs :
      /\ m.type = "grant" /\ m.n = n
      /\ nSt[n] = "up"
      /\ msgs' = msgs \ {m}
      /\ LET lo == Max(LeaseRealMin - m.age, 0)
             hi == Max(LeaseRealMax - m.age, 0)
         IN IF m.inc = nInc[n] /\ hi > nHi[n]
            THEN /\ nLo' = [nLo EXCEPT ![n] = lo]
                 /\ nHi' = [nHi EXCEPT ![n] = hi]
                 /\ cap' = [a \in Attempts |->
                              IF OnNode(a, n) /\ cap[a].prov
                              THEN [cap[a] EXCEPT !.lo = lo, !.kill = hi + K] ELSE cap[a]]
            ELSE UNCHANGED <<nLo, nHi, cap>>
      /\ UNCHANGED <<nSt, nInc, nGen, renewAge, intake, turn, cUp, silent, cSess, cInc,
                     cNGen, cLapsed, revoked, att, frame, reported, gwUp, slice, revokeAge,
                     delivered, started, deliveries, egress>>

\* `Accepted(attempt)` is fsynced before the dispatch is acknowledged.
NodeAccept(n) ==
    \E m \in msgs :
      /\ m.type = "dispatch" /\ m.n = n
      /\ nSt[n] = "up"
      /\ msgs' = msgs \ {m}
      /\ IF m.inc = nInc[n] /\ intake[n][m.a] = "none"
         THEN intake' = [intake EXCEPT ![n][m.a] = "accepted"]
         ELSE UNCHANGED intake
      /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, renewAge, cap, turn, cUp, silent, cSess,
                     cInc, cNGen, cLapsed, revoked, att, frame, reported, gwUp, slice,
                     revokeAge, delivered, started, deliveries, egress>>

\* `Started` is fsynced before the container is created; the provider refuses an
\* assignment whose lease_until is absent or already past.
NodeStart(n, a) ==
    /\ nSt[n] = "up" /\ nInc[n] # 0
    /\ intake[n][a] = "accepted"
    /\ MUTANT = "start_before_intake" => ~(started[a] /\ cap[a].node = n)
    /\ nHi[n] > 0
    /\ intake' = [intake EXCEPT ![n][a] =
                    IF MUTANT = "start_before_intake" THEN "accepted" ELSE "started"]
    /\ cap' = [cap EXCEPT ![a] = [NoCap EXCEPT !.run = TRUE, !.node = n, !.prov = TRUE,
                                              !.lo = nLo[n], !.kill = nHi[n] + K]]
    /\ turn' = [turn EXCEPT ![a] = HARNESS_IN_NODE]
    /\ started' = [started EXCEPT ![a] = TRUE]
    /\ deliveries' = [deliveries EXCEPT ![a] = @ + 1]
    /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, renewAge, cUp, silent, cSess, cInc, cNGen,
                   cLapsed, revoked, att, frame, reported, gwUp, slice, revokeAge,
                   delivered, msgs, egress>>

\* The mutant's late fsync of `Started`.
NodeLateStartedFsync(n, a) ==
    /\ MUTANT = "start_before_intake"
    /\ nSt[n] = "up" /\ intake[n][a] = "accepted" /\ started[a] /\ cap[a].node = n
    /\ intake' = [intake EXCEPT ![n][a] = "started"]
    /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, renewAge, cap, turn, cUp, silent, cSess,
                   cInc, cNGen, cLapsed, revoked, att, frame, reported, gwUp, slice,
                   revokeAge, delivered, msgs, started, deliveries, egress>>

\* The capsule ends on its own; the node reports the outcome.
CapsuleExit(a) ==
    /\ cap[a].run
    /\ nSt[cap[a].node] # "suspended"
    /\ cap' = [cap EXCEPT ![a].run = FALSE, ![a].exited = TRUE]
    /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, renewAge, intake, turn, cUp, silent, cSess,
                   cInc, cNGen, cLapsed, revoked, att, frame, reported, gwUp, slice,
                   revokeAge, delivered, msgs, started, deliveries, egress>>

NodeReport(n, a) ==
    /\ nSt[n] = "up" /\ nInc[n] # 0
    /\ cap[a].exited /\ cap[a].node = n
    /\ msgs' = msgs \cup {[type |-> "result", n |-> n, inc |-> nInc[n], age |-> 0, a |-> a]}
    /\ cap' = [cap EXCEPT ![a].exited = FALSE]
    /\ turn' = [turn EXCEPT ![a] = FALSE]
    /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, renewAge, intake, cUp, silent, cSess, cInc,
                   cNGen, cLapsed, revoked, att, frame, reported, gwUp, slice, revokeAge,
                   delivered, started, deliveries, egress>>

\* The provider's watch loop: CLOCK_BOOTTIME past D writes `1` to cgroup.kill. The
\* mutant runs that loop in the node process instead.
ProviderKill(a) ==
    /\ cap[a].run /\ cap[a].prov /\ cap[a].lo = 0
    /\ IF MUTANT = "kill_on_node_process"
       THEN nSt[cap[a].node] = "up"
       ELSE nSt[cap[a].node] # "suspended"
    /\ cap' = [cap EXCEPT ![a].run = FALSE]
    /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, renewAge, intake, turn, cUp, silent, cSess,
                   cInc, cNGen, cLapsed, revoked, att, frame, reported, gwUp, slice,
                   revokeAge, delivered, msgs, started, deliveries, egress>>

\* A provider whose node died sees stdin EOF and cancels: it kills the container.
ProviderCancel(a) ==
    /\ cap[a].run /\ cap[a].prov /\ nSt[cap[a].node] = "down"
    /\ cap' = [cap EXCEPT ![a].run = FALSE]
    /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, renewAge, intake, turn, cUp, silent, cSess,
                   cInc, cNGen, cLapsed, revoked, att, frame, reported, gwUp, slice,
                   revokeAge, delivered, msgs, started, deliveries, egress>>

ProviderDie(a) ==
    /\ ALLOW_PROVIDER_DEATH
    /\ cap[a].run /\ cap[a].prov
    /\ cap' = [cap EXCEPT ![a].prov = FALSE, ![a].contain = K_CONTAIN,
                          ![a].excused = @ \/ nSt[cap[a].node] = "stalled"
                                           \/ (EXCUSE_CRASHED /\ nSt[cap[a].node] = "down")]
    /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, renewAge, intake, turn, cUp, silent, cSess,
                   cInc, cNGen, cLapsed, revoked, att, frame, reported, gwUp, slice,
                   revokeAge, delivered, msgs, started, deliveries, egress>>

\* A live node answers a dead provider with kill_and_contain.
NodeContain(a) ==
    /\ cap[a].run /\ ~cap[a].prov /\ nSt[cap[a].node] = "up"
    /\ cap' = [cap EXCEPT ![a].run = FALSE]
    /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, renewAge, intake, turn, cUp, silent, cSess,
                   cInc, cNGen, cLapsed, revoked, att, frame, reported, gwUp, slice,
                   revokeAge, delivered, msgs, started, deliveries, egress>>

\* Every running capsule on n whose provider is dead lives through the double fault.
ExcuseDoubleFault(n) ==
    cap' = [a \in Attempts |->
              IF OnNode(a, n) /\ ~cap[a].prov THEN [cap[a] EXCEPT !.excused = TRUE] ELSE cap[a]]

NodeStall(n) ==
    /\ ALLOW_STALL /\ nSt[n] = "up"
    /\ nSt' = [nSt EXCEPT ![n] = "stalled"]
    /\ ExcuseDoubleFault(n)
    /\ UNCHANGED <<nInc, nGen, nLo, nHi, renewAge, intake, turn, cUp, silent, cSess, cInc,
                   cNGen, cLapsed, revoked, att, frame, reported, gwUp, slice, revokeAge,
                   delivered, msgs, started, deliveries, egress>>

NodeUnstall(n) ==
    /\ nSt[n] = "stalled"
    /\ nSt' = [nSt EXCEPT ![n] = "up"]
    /\ UNCHANGED <<nInc, nGen, nLo, nHi, renewAge, intake, cap, turn, cUp, silent, cSess,
                   cInc, cNGen, cLapsed, revoked, att, frame, reported, gwUp, slice,
                   revokeAge, delivered, msgs, started, deliveries, egress>>

NodeCrash(n) ==
    /\ ALLOW_CRASH /\ nSt[n] \in {"up", "stalled"}
    /\ nSt' = [nSt EXCEPT ![n] = "down"]
    /\ nInc' = [nInc EXCEPT ![n] = 0]
    /\ nLo' = [nLo EXCEPT ![n] = -1]
    /\ nHi' = [nHi EXCEPT ![n] = -1]
    /\ turn' = [a \in Attempts |-> IF cap[a].node = n THEN FALSE ELSE turn[a]]
    /\ IF EXCUSE_CRASHED THEN ExcuseDoubleFault(n) ELSE UNCHANGED cap
    /\ UNCHANGED <<nGen, renewAge, intake, cUp, silent, cSess, cInc, cNGen, cLapsed,
                   revoked, att, frame, reported, gwUp, slice, revokeAge, delivered, msgs,
                   started, deliveries, egress>>

NodeBoot(n) ==
    /\ nSt[n] = "down"
    /\ nSt' = [nSt EXCEPT ![n] = "up"]
    /\ UNCHANGED <<nInc, nGen, nLo, nHi, renewAge, intake, cap, turn, cUp, silent, cSess,
                   cInc, cNGen, cLapsed, revoked, att, frame, reported, gwUp, slice,
                   revokeAge, delivered, msgs, started, deliveries, egress>>

\* The data directory is replaced while the node is down: a new node generation.
NodeWipe(n) ==
    /\ ALLOW_NODE_WIPE /\ nSt[n] = "down" /\ nGen[n] = 1
    /\ nGen' = [nGen EXCEPT ![n] = 2]
    /\ intake' = [intake EXCEPT ![n] = [a \in Attempts |-> "none"]]
    /\ UNCHANGED <<nSt, nInc, nLo, nHi, renewAge, cap, turn, cUp, silent, cSess, cInc,
                   cNGen, cLapsed, revoked, att, frame, reported, gwUp, slice, revokeAge,
                   delivered, msgs, started, deliveries, egress>>

NodeSuspend(n) ==
    /\ ALLOW_SUSPEND /\ nSt[n] = "up"
    /\ nSt' = [nSt EXCEPT ![n] = "suspended"]
    /\ cap' = [a \in Attempts |-> IF OnNode(a, n) THEN [cap[a] EXCEPT !.excused = TRUE]
                                  ELSE cap[a]]
    /\ UNCHANGED <<nInc, nGen, nLo, nHi, renewAge, intake, turn, cUp, silent, cSess, cInc,
                   cNGen, cLapsed, revoked, att, frame, reported, gwUp, slice, revokeAge,
                   delivered, msgs, started, deliveries, egress>>

NodeThaw(n) ==
    /\ nSt[n] = "suspended"
    /\ nSt' = [nSt EXCEPT ![n] = "up"]
    /\ UNCHANGED <<nInc, nGen, nLo, nHi, renewAge, intake, cap, turn, cUp, silent, cSess,
                   cInc, cNGen, cLapsed, revoked, att, frame, reported, gwUp, slice,
                   revokeAge, delivered, msgs, started, deliveries, egress>>

\* A node whose session dropped while its lease is valid sends Resume; kata-control
\* accepts it unless it already settled that incarnation (lease_lapsed: kill, sweep,
\* Hello) or the key is revoked.
NodeResume(n) ==
    /\ nSt[n] = "up" /\ nInc[n] # 0 /\ ~cSess[n] /\ cUp
    /\ nHi[n] > 0
    /\ IF nInc[n] = cInc[n] /\ nInc[n] \notin cLapsed[n] /\ ~revoked[n]
       THEN /\ cSess' = [cSess EXCEPT ![n] = TRUE]
            /\ UNCHANGED nInc
       ELSE /\ nInc' = [nInc EXCEPT ![n] = 0]
            /\ UNCHANGED cSess
    /\ UNCHANGED <<nSt, nGen, nLo, nHi, renewAge, intake, cap, turn, cUp, silent, cInc,
                   cNGen, cLapsed, revoked, att, frame, reported, gwUp, slice, revokeAge,
                   delivered, msgs, started, deliveries, egress>>

\* A partition drops the session and every message in flight to or from n.
Partition(n) ==
    /\ ALLOW_PARTITION
    /\ cSess[n] \/ \E m \in msgs : m.n = n
    /\ cSess' = [cSess EXCEPT ![n] = FALSE]
    /\ msgs' = {m \in msgs : m.n # n}
    /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, renewAge, intake, cap, turn, cUp, silent,
                   cInc, cNGen, cLapsed, revoked, att, frame, reported, gwUp, slice,
                   revokeAge, delivered, started, deliveries, egress>>

-----------------------------------------------------------------------------
(* Control plane *)

Grantable(n, inc) == cSess[n] /\ inc = cInc[n] /\ inc \notin cLapsed[n] /\ ~revoked[n]

\* A renewal is granted on a live session of the welcomed incarnation; t_recv is now.
CtlRecvRenew ==
    \E m \in msgs :
      /\ m.type = "renew" /\ cUp
      /\ msgs' = (msgs \ {m}) \cup
            (IF Grantable(m.n, m.inc)
             THEN {[type |-> "grant", n |-> m.n, inc |-> m.inc, age |-> m.age, a |-> 0]}
             ELSE {})
      /\ silent' = IF Grantable(m.n, m.inc) THEN [silent EXCEPT ![m.n] = 0] ELSE silent
      /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, renewAge, intake, cap, turn, cUp, cSess,
                     cInc, cNGen, cLapsed, revoked, att, frame, reported, gwUp, slice,
                     revokeAge, delivered, started, deliveries, egress>>

\* The retry chain: attempt a runs only after a-1 settled PROVEN NOT PERFORMED. An
\* embedded-harness dispatch is held while the gateway is down (its slice must be
\* journaled before the assignment is sent).
CtlDispatch(a, n, kind) ==
    /\ cUp /\ att[a].st = "none"
    /\ IF a = 1 THEN TRUE ELSE att[a - 1].verdict = "NOT_PERFORMED"
    /\ cInc[n] # 0 /\ Grantable(n, cInc[n])
    /\ kind = "embedded" => gwUp
    /\ att' = [att EXCEPT ![a] = [st |-> "dispatched", node |-> n, inc |-> cInc[n],
                                  kind |-> kind, verdict |-> "-", ev |-> "-"]]
    /\ slice' = [slice EXCEPT ![a] = IF kind = "embedded" THEN "open" ELSE "none"]
    /\ gwOpen' = [gwOpen EXCEPT ![a] = kind = "embedded"]
    /\ frame' = [frame EXCEPT ![a] = "no"]
    /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, renewAge, intake, cap, turn, cUp, silent,
                   cSess, cInc, cNGen, cLapsed, revoked, reported, gwUp, revokeAge,
                   delivered, msgs, started, deliveries, gwRevoked, badMark,
                   markAfterRevoke>>

CtlSendFrame(a) ==
    /\ cUp /\ att[a].st = "dispatched" /\ frame[a] = "no"
    /\ cSess[att[a].node] /\ att[a].inc = cInc[att[a].node]
    /\ frame' = [frame EXCEPT ![a] = "yes"]
    /\ msgs' = msgs \cup {[type |-> "dispatch", n |-> att[a].node, inc |-> att[a].inc,
                           age |-> 0, a |-> a]}
    /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, renewAge, intake, cap, turn, cUp, silent,
                   cSess, cInc, cNGen, cLapsed, revoked, att, reported, gwUp, slice,
                   revokeAge, delivered, started, deliveries, egress>>

\* A result frame, fenced by node and incarnation, settles the attempt with the
\* reported outcome (an embedded-harness attempt once its slice closes).
CtlRecvResult ==
    \E m \in msgs :
      /\ m.type = "result" /\ cUp
      /\ msgs' = msgs \ {m}
      /\ IF /\ \/ att[m.a].st = "dispatched"
               \/ MUTANT = "result_after_settlement" /\ att[m.a].st = "settled"
            /\ att[m.a].node = m.n /\ att[m.a].inc = m.inc
         THEN /\ reported' = [reported EXCEPT ![m.a] = TRUE]
              /\ IF att[m.a].kind = "shell"
                 THEN /\ att' = [att EXCEPT ![m.a].st = "settled", ![m.a].verdict = "OUTCOME"]
                      /\ UNCHANGED revokeAge
                 ELSE /\ att' = [att EXCEPT ![m.a].st = "settling", ![m.a].ev = "possible"]
                      /\ revokeAge' = [revokeAge EXCEPT ![m.a] = 0]
         ELSE UNCHANGED <<reported, att, revokeAge>>
      /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, renewAge, intake, cap, turn, cUp, silent,
                     cSess, cInc, cNGen, cLapsed, revoked, frame, gwUp, slice, delivered,
                     started, deliveries, egress>>

\* A silent node: W has passed on kata-control's clock since the last granted renewal
\* (or since boot). Its open attempts settle from kata-control's own records.
CtlSettleSilent(n) ==
    /\ cUp /\ cInc[n] # 0 /\ cInc[n] \notin cLapsed[n]
    /\ \E a \in Attempts : att[a].st = "dispatched" /\ att[a].node = n
    /\ silent[n] >= SettleRealMin
    /\ cLapsed' = [cLapsed EXCEPT ![n] = @ \cup {cInc[n]}]
    /\ cSess' = [cSess EXCEPT ![n] = FALSE]
    /\ SettleOpen(n, FrameEvidence)
    /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, renewAge, intake, cap, turn, cUp, silent,
                   cInc, cNGen, revoked, frame, reported, gwUp, slice, delivered, msgs,
                   started, deliveries, egress>>

\* `kata node revoke`: `revoked` is committed first; the handshake refuses the key and
\* the gateway its requests. Its attempts settle as a silent node's do (ADR §3).
CtlRevoke(n) ==
    /\ ALLOW_REVOKE /\ cUp /\ ~revoked[n]
    /\ revoked' = [revoked EXCEPT ![n] = TRUE]
    /\ cSess' = [cSess EXCEPT ![n] = FALSE]
    /\ IF MUTANT = "settle_at_revoke" /\ cInc[n] # 0
       THEN /\ cLapsed' = [cLapsed EXCEPT ![n] = @ \cup {cInc[n]}]
            /\ SettleOpen(n, FrameEvidence)
       ELSE UNCHANGED <<cLapsed, att, revokeAge>>
    /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, renewAge, intake, cap, turn, cUp, silent,
                   cInc, cNGen, frame, reported, gwUp, slice, delivered, msgs, started,
                   deliveries, egress>>

\* kata-control keeps no lease state on disk: t_recv, sessions and whether a frame was
\* written are lost, and so is everything in flight to it.
CtlCrash ==
    /\ ALLOW_CONTROL_RESTART /\ cUp
    /\ cUp' = FALSE
    /\ cSess' = [n \in Nodes |-> FALSE]
    /\ frame' = [a \in Attempts |-> IF att[a].st = "dispatched" THEN "unknown" ELSE frame[a]]
    /\ msgs' = {m \in msgs : m.type \in {"grant", "dispatch"}}
    /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, renewAge, intake, cap, turn, silent, cInc,
                   cNGen, cLapsed, revoked, att, reported, gwUp, slice, revokeAge,
                   delivered, started, deliveries, egress>>

\* On boot it waits W from boot before settling any node (the mutant does not).
CtlBoot ==
    /\ ~cUp
    /\ cUp' = TRUE
    /\ silent' = [n \in Nodes |-> IF MUTANT = "no_boot_wait" THEN SettleRealMin ELSE 0]
    /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, renewAge, intake, cap, turn, cSess, cInc,
                   cNGen, cLapsed, revoked, att, frame, reported, gwUp, slice, revokeAge,
                   delivered, msgs, started, deliveries, egress>>

-----------------------------------------------------------------------------
(* Gateway and slices *)

\* A model request from the attempt's live requester (the capsule, or before S4 the
\* node-resident turn) whose output reaches the node. The gateway checks it against
\* its own journal and mirror: the slice open there, the node not revoked there; the
\* mark is journaled before the first upstream byte.
ModelOutput(a) ==
    /\ gwUp /\ ~delivered[a] /\ att[a].node # NoNode
    /\ gwOpen[a] \/ (MUTANT = "mark_on_closed_slice" /\ slice[a] # "none")
    /\ ~gwRevoked[att[a].node] \/ MUTANT = "mark_despite_revocation"
    /\ IF HARNESS_IN_NODE
       THEN turn[a] /\ nSt[cap[a].node] = "up"
       ELSE cap[a].run /\ nSt[cap[a].node] # "suspended"
    /\ delivered' = [delivered EXCEPT ![a] = TRUE]
    /\ badMark' = (badMark \/ slice[a] = "closed" \/ gwRevoked[att[a].node])
    /\ markAfterRevoke' = (markAfterRevoke \/ revoked[att[a].node])
    /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, renewAge, intake, cap, turn, cUp, silent,
                   cSess, cInc, cNGen, cLapsed, revoked, att, frame, reported, gwUp, slice,
                   revokeAge, msgs, started, deliveries, gwOpen, gwRevoked>>

\* The gateway processes SliceRevoke (sent, and resent on every connection, from the
\* moment settlement starts): it stops admitting marks on the slice and answers.
GwCloseSlice(a) ==
    /\ cUp /\ gwUp /\ gwOpen[a] /\ revokeAge[a] # -1
    /\ gwOpen' = [gwOpen EXCEPT ![a] = FALSE]
    /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, renewAge, intake, cap, turn, cUp, silent,
                   cSess, cInc, cNGen, cLapsed, revoked, att, frame, reported, gwUp, slice,
                   revokeAge, delivered, msgs, started, deliveries, gwRevoked, badMark,
                   markAfterRevoke>>

\* The gateway learns a revocation over its session with kata-control.
GwLearnRevoke(n) ==
    /\ cUp /\ gwUp /\ revoked[n] /\ ~gwRevoked[n]
    /\ gwRevoked' = [gwRevoked EXCEPT ![n] = TRUE]
    /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, renewAge, intake, cap, turn, cUp, silent,
                   cSess, cInc, cNGen, cLapsed, revoked, att, frame, reported, gwUp, slice,
                   revokeAge, delivered, msgs, started, deliveries, gwOpen, badMark,
                   markAfterRevoke>>

\* SliceClosed with every mark; settlement waits for it.
CtlSliceClosed(a) ==
    /\ cUp /\ gwUp /\ att[a].st = "settling" /\ slice[a] = "open" /\ ~gwOpen[a]
    /\ slice' = [slice EXCEPT ![a] = "closed"]
    /\ att' = [att EXCEPT ![a].st = "settled", ![a].verdict = MarkVerdict(a)]
    /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, renewAge, intake, cap, turn, cUp, silent,
                   cSess, cInc, cNGen, cLapsed, revoked, frame, reported, gwUp, revokeAge,
                   delivered, msgs, started, deliveries, egress>>

\* G without SliceClosed: the slice is unclosed (it freezes its scopes: SliceBudget),
\* and until the gateway processes SliceRevoke a live requester can still be marked on
\* it (ADR §5's stated exception).
CtlSliceTimeout(a) ==
    /\ cUp /\ att[a].st = "settling" /\ slice[a] = "open"
    /\ revokeAge[a] >= G_WAIT
    /\ slice' = [slice EXCEPT ![a] = "unclosed"]
    /\ att' = [att EXCEPT ![a].st = "settled", ![a].verdict = TimeoutVerdict(a)]
    /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, renewAge, intake, cap, turn, cUp, silent,
                   cSess, cInc, cNGen, cLapsed, revoked, frame, reported, gwUp, revokeAge,
                   delivered, msgs, started, deliveries, egress>>

\* The mutant: marks judged from what was adopted so far, without SliceClosed.
CtlSettleWithoutClose(a) ==
    /\ MUTANT = "settle_before_slice_close"
    /\ cUp /\ att[a].st = "settling" /\ slice[a] = "open"
    /\ att' = [att EXCEPT ![a].st = "settled", ![a].verdict = MarkVerdict(a)]
    /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, renewAge, intake, cap, turn, cUp, silent,
                   cSess, cInc, cNGen, cLapsed, revoked, frame, reported, gwUp, slice,
                   revokeAge, delivered, msgs, started, deliveries, egress>>

\* A resent SliceRevoke closes an unclosed slice once the gateway answers.
GwLateClose(a) ==
    /\ gwUp /\ slice[a] = "unclosed" /\ ~gwOpen[a]
    /\ slice' = [slice EXCEPT ![a] = "closed"]
    /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, renewAge, intake, cap, turn, cUp, silent,
                   cSess, cInc, cNGen, cLapsed, revoked, att, frame, reported, gwUp,
                   revokeAge, delivered, msgs, started, deliveries, egress>>

GwDown ==
    /\ ALLOW_GATEWAY_DOWN /\ gwUp
    /\ gwUp' = FALSE
    /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, renewAge, intake, cap, turn, cUp, silent,
                   cSess, cInc, cNGen, cLapsed, revoked, att, frame, reported, slice,
                   revokeAge, delivered, msgs, started, deliveries, egress>>

GwUp ==
    /\ ~gwUp
    /\ gwUp' = TRUE
    /\ UNCHANGED <<nSt, nInc, nGen, nLo, nHi, renewAge, intake, cap, turn, cUp, silent,
                   cSess, cInc, cNGen, cLapsed, revoked, att, frame, reported, slice,
                   revokeAge, delivered, msgs, started, deliveries, egress>>

-----------------------------------------------------------------------------

\* The adversary's moves, each spending one unit of the fault budget.
Fault ==
    \/ \E n \in Nodes :
         \/ NodeStall(n) \/ NodeCrash(n) \/ NodeWipe(n) \/ NodeSuspend(n)
         \/ Partition(n) \/ CtlRevoke(n)
    \/ \E a \in Attempts : ProviderDie(a)
    \/ CtlCrash \/ GwDown

Step ==
    \/ Tick
    \/ \E n \in Nodes :
         \/ NodeSweep(n) \/ NodeHello(n) \/ NodeLeaseLapse(n) \/ NodeRenew(n)
         \/ NodeRecvGrant(n) \/ NodeAccept(n) \/ NodeUnstall(n) \/ NodeBoot(n)
         \/ NodeThaw(n) \/ NodeResume(n) \/ CtlSettleSilent(n) \/ GwLearnRevoke(n)
         \/ \E a \in Attempts : NodeStart(n, a) \/ NodeReport(n, a) \/ NodeLateStartedFsync(n, a)
         \/ \E a \in Attempts, k \in Kinds : CtlDispatch(a, n, k)
    \/ \E a \in Attempts :
         \/ CapsuleExit(a) \/ ProviderKill(a) \/ ProviderCancel(a) \/ NodeContain(a)
         \/ CtlSendFrame(a) \/ ModelOutput(a) \/ GwCloseSlice(a) \/ CtlSliceClosed(a)
         \/ CtlSliceTimeout(a) \/ CtlSettleWithoutClose(a) \/ GwLateClose(a)
    \/ CtlRecvRenew \/ CtlRecvResult \/ CtlBoot \/ GwUp

Next ==
    \/ faults < MaxFaults /\ Fault /\ faults' = faults + 1
    \/ Step /\ UNCHANGED faults

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Invariants *)

TypeOK ==
    /\ \A n \in Nodes : nSt[n] \in {"up", "stalled", "down", "suspended"}
    /\ \A a \in Attempts : att[a].st \in {"none", "dispatched", "settling", "settled"}
                           /\ att[a].verdict \in Verdicts

\* ADR §4: the subtree is empty before settlement, against a node that stops, stalls,
\* crashes or is partitioned, and a provider that dies under a live node. Outside the
\* named adversary steps: no capsule runs after its settlement.
NoCapsuleAfterSettlement ==
    \A a \in Attempts : (att[a].st = "settled" /\ cap[a].run) => cap[a].excused

\* "A capsule is never delivered twice", and the stage never runs in two capsules at
\* once (a re-run starts only after its predecessor's capsule is gone).
NoDoubleDelivery ==
    /\ \A a \in Attempts : deliveries[a] <= 1
    /\ \A a, b \in Attempts :
         (a # b /\ cap[a].run /\ cap[b].run) => (cap[a].excused \/ cap[b].excused)

\* NOT PERFORMED only when nothing could have happened: no container for a shell
\* attempt; for an embedded-harness one, no mark ever delivered output toward the node
\* (checked in every later state too, so a mark admitted after the verdict is caught).
NotPerformedIsSound ==
    \A a \in Attempts :
      att[a].verdict = "NOT_PERFORMED" =>
        /\ ~delivered[a]
        /\ att[a].kind = "shell" => ~started[a]

\* Past G (an unclosed slice): a reported outcome is kept, never turned AMBIGUOUS.
PastGKeepsReportedOutcome ==
    \A a \in Attempts :
      (slice[a] = "unclosed" /\ att[a].st = "settled" /\ reported[a]) =>
        att[a].verdict = "OUTCOME"

\* Plan M0: no mark on a closed slice or a revoked node. Closed: kata-control holds the
\* slice's SliceClosed (the gateway stopped admitting before it answered). Revoked: the
\* gateway's mirror holds the revocation.
NoMarkOnClosedSliceOrRevokedNode == ~badMark

\* ADR §3, literally: from the commit of `revoked` on, "the gateway refuses the node's
\* requests" (refuted: the mirror learns it later, F4).
NoMarkAfterRevokeCommitted == ~markAfterRevoke

\* Verdicts only move forward.
VerdictsOnlyForward ==
    [][\A a \in Attempts : att[a].st = "settled" => att'[a] = att[a]]_vars

=============================================================================
