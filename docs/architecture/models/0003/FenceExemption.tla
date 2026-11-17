--------------------------- MODULE FenceExemption ---------------------------
(***************************************************************************)
(* Plan M0's last question: does `fence_inbound_attempt_frame`'s           *)
(* NULL-placement exemption survive placement-in-dispatch?                 *)
(*                                                                         *)
(* Today (crates/core/src/operational/ingress_fence.rs) an attempt whose   *)
(* `attempts.worker_id` is NULL skips the WrongWorker comparison, because  *)
(* a genuine terminal can fold between the dispatch commit and the         *)
(* placement write, and a worker sends its terminal once: refusing it      *)
(* would drop the outcome (a redelivery wedge). The epoch comparison still *)
(* runs. ADR 0003 (§4, S2's L2b) records the placement, node and           *)
(* incarnation in the dispatch transaction itself.                         *)
(*                                                                         *)
(* One attempt, dispatched (and re-dispatched after a park) to authenticated *)
(* nodes; the node it was sent to reports its terminal once; any other    *)
(* admitted node may forge a frame for it at any epoch (epochs are small   *)
(* integers, so guessable).                                                *)
(*                                                                         *)
(* PLACE_IN_DISPATCH: the placement commits with the dispatch (ADR 0003)   *)
(* or in a later write (today). EXEMPTION: the NULL-placement skip. MUTANT *)
(* removes one arm of the fence for the RED half.                          *)
(***************************************************************************)
EXTENDS Integers

CONSTANTS Nodes, MaxEpoch, PLACE_IN_DISPATCH, EXEMPTION, MUTANT

Mutants == {"none",
            "no_placement_check",   \* the WrongWorker arm removed
            "refuse_unplaced"}      \* a NULL placement refused whatever EXEMPTION says
ASSUME MUTANT \in Mutants

NULL == "null"
NoOwed == [node |-> NULL, epoch |-> 0]

VARIABLES
    st,         \* "pending" | "dispatched" | "parked" | "terminal"
    epoch,      \* the attempt's durable lease epoch
    placed,     \* the durable placement, or NULL
    placeWrite, \* a placement write still to come (today's split), or NULL
    sentTo,     \* [1..MaxEpoch -> Nodes \cup {NULL}] who each epoch's dispatch went to
    owed,       \* the genuine terminal a node still has to send: [node, epoch] (NoOwed: none)
    foreign,    \* a frame from a node the attempt was not dispatched to was accepted
    wedged      \* a genuine terminal was refused (its outcome is gone)

vars == <<st, epoch, placed, placeWrite, sentTo, owed, foreign, wedged>>

Init ==
    /\ st = "pending" /\ epoch = 0 /\ placed = NULL /\ placeWrite = NULL
    /\ sentTo = [e \in 1 .. MaxEpoch |-> NULL]
    /\ owed = NoOwed /\ foreign = FALSE /\ wedged = FALSE

\* The fence's placement and epoch arms (the version and impersonation arms pass: the
\* sender is authenticated and speaks the protocol).
Accepts(sender, e) ==
    /\ CASE MUTANT = "no_placement_check" -> TRUE
         [] placed = NULL -> EXEMPTION /\ MUTANT # "refuse_unplaced"
         [] OTHER -> sender = placed
    /\ e = epoch

Dispatch(n) ==
    /\ st \in {"pending", "parked"} /\ epoch < MaxEpoch /\ owed = NoOwed
    /\ epoch' = epoch + 1
    /\ st' = "dispatched"
    /\ sentTo' = [sentTo EXCEPT ![epoch + 1] = n]
    /\ IF PLACE_IN_DISPATCH
       THEN placed' = n /\ placeWrite' = NULL
       ELSE placed' = NULL /\ placeWrite' = n
    /\ owed' = [node |-> n, epoch |-> epoch + 1]
    /\ UNCHANGED <<foreign, wedged>>

\* Today's later placement write.
PlaceWrite ==
    /\ placeWrite # NULL /\ st = "dispatched"
    /\ placed' = placeWrite /\ placeWrite' = NULL
    /\ UNCHANGED <<st, epoch, sentTo, owed, foreign, wedged>>

\* A dispatched attempt parks: worker_id goes NULL while parked; the node that held it
\* is told and owes nothing.
Park ==
    /\ st = "dispatched" /\ placeWrite = NULL
    /\ st' = "parked" /\ placed' = NULL /\ owed' = NoOwed
    /\ UNCHANGED <<epoch, placeWrite, sentTo, foreign, wedged>>

\* The node the attempt was sent to reports its terminal, once.
GenuineTerminal ==
    /\ owed # NoOwed /\ st = "dispatched"
    /\ IF Accepts(owed.node, owed.epoch)
       THEN /\ st' = "terminal" /\ UNCHANGED wedged
       ELSE /\ wedged' = TRUE /\ UNCHANGED st
    /\ owed' = NoOwed
    /\ UNCHANGED <<epoch, placed, placeWrite, sentTo, foreign>>

\* Another admitted node forges a frame at any epoch.
Forged(m, e) ==
    /\ st # "terminal" /\ e \in 1 .. MaxEpoch /\ sentTo[e] # m
    /\ Accepts(m, e)
    /\ foreign' = TRUE
    /\ UNCHANGED <<st, epoch, placed, placeWrite, sentTo, owed, wedged>>

Next ==
    \/ \E n \in Nodes : Dispatch(n)
    \/ PlaceWrite \/ Park \/ GenuineTerminal
    \/ \E m \in Nodes, e \in 1 .. MaxEpoch : Forged(m, e)

Spec == Init /\ [][Next]_vars

\* WrongWorker holds: no node reports on an attempt not dispatched to it.
NoForeignFrameAccepted == ~foreign

\* The exemption's reason: a genuine terminal is never refused.
NoGenuineTerminalRefused == ~wedged

=============================================================================
