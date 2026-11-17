----------------------------- MODULE ForgeIntent -----------------------------
(***************************************************************************)
(* ADR 0003 "Effects" and E1 as a checked model: a stage's forge export,   *)
(* a push of `kata/<execution>` then a pull request carrying kata's        *)
(* marker. kata-control reads the remote first (`remote_branch_head`);     *)
(* that answer is the push's lease (`push_forge_branch_expecting`), and a  *)
(* failed read leaves no intent (PROVEN NOT PERFORMED). The pull request   *)
(* is looked up the same way before its intent (`find_open_pr`): an open   *)
(* one is adopted under no intent, and a failed lookup leaves no intent.   *)
(* Each wire effect's intent row commits after that read, immediately      *)
(* before the first byte; its receipt commits after. After a crash, an     *)
(* intent without a receipt waits for its observer's verdict: the remote   *)
(* ref for the push, a pull request carrying the intent's marker, in any   *)
(* state, for the PR. Nothing is redone without a verdict that it was not  *)
(* performed. A push the remote refuses (the branch moved off the lease)   *)
(* waits for the same verdict, its command's error recorded on the intent; *)
(* NOT PERFORMED then fails the export instead of pushing again. An        *)
(* observer read the remote does not ANSWER leaves the intent open for     *)
(* the next ask, its count one higher; an intent counted                   *)
(* MaxAsks times is settled UNCLASSIFIED in a step of its own (the code's  *)
(* second transaction) and is never asked again. A read that answers with  *)
(* a state contradicting both verdicts — a foreign head, a listing past    *)
(* its bound — settles UNCLASSIFIED at once.                               *)
(*                                                                         *)
(* The remote is outside kata: unreachable at any moment, someone else can *)
(* push to the branch, delete it, close the pull request or open more on   *)
(* kata's head than the marker listing reads, and (the stated residual) a  *)
(* human can delete the marker.                                            *)
(***************************************************************************)
EXTENDS Integers

CONSTANTS MaxFaults,
          MaxAsks,      \* the unanswered observer reads an open intent is asked, the last
                        \* of which settles it UNCLASSIFIED
          EXCUSE_ABA,   \* TRUE: the branch back on the lease after kata's push and before
                        \* its observer's first answer is a stated residual (finding F9)
          MUTANT

ASSUME MaxAsks \in Nat \ {0}

Mutants == {"none",
            "no_pre_intent_read",           \* the push is not leased on a read before its intent
            "intent_after_push",            \* the push's intent row commits after the push
            "open_prs_only",                \* the observer lists only open pull requests
            "redo_without_verdict",         \* an intent a crash left is redone at once
            "unreachable_is_not_performed", \* an unreachable remote read as "not performed"
            "naive_push_observer",          \* any head but kata's commit read as "not performed"
            "unread_is_unclassified",       \* an unanswered read settles UNCLASSIFIED at once
            "unbounded_reask",              \* an unanswered read never settles the intent
            "contradiction_reasked",        \* a contradicting state is asked again, as if unread
            "no_pr_lookup",                 \* the pull request's intent with no lookup before it
            "unread_lookup_is_none",        \* a lookup the forge did not answer read as "none open"
            "ask_at_bound",                 \* an intent counted MaxAsks times is asked again
            "beyond_bound_unanswered"}      \* a listing past its bound counted as unanswered

ASSUME MUTANT \in Mutants

PRs == 1 .. 2

VARIABLES
    \* ---- the remote: a branch head and pull requests on kata's head ----
    reachable,
    head,       \* "none" | "kata" (our commit) | "other", "other2" (someone else's)
    prs,        \* [PRs -> "absent" | "open" | "closed"]
    marked,     \* [PRs -> BOOLEAN] the body carries the intent's marker
    crowded,    \* more pull requests on kata's head than the marker listing reads
    \* ---- kata-control ----
    up,
    read,       \* in memory: the head read before the push intent ("unread")
    looked,     \* in memory: the lookup before the pull request's intent found none open
    push,       \* durable: "none" | "intent" | "failed" (the intent, with the push command's
                \* error recorded) | "receipt"
    lease,      \* durable, with the push intent: the head it may replace ("any": none)
    pr,         \* durable: "none" | "intent" | "receipt"
    orphan,     \* durable: [push, pr] intents owed an observer's verdict: a crash left them,
                \* or the push command failed
    asks,       \* durable, on the open intent: its observer's reads the remote did not answer
    wire,       \* in memory: the push or create in flight has landed, receipt not written
    exported,   \* "running" | "not_performed" | "pr_unread" | "done" | "unclassified"
    \* ---- ghosts ----
    pushes, creates,        \* wire effects that reached the remote
    unintended,             \* a wire effect reached the remote with no intent committed
    overUnread,             \* a push replaced a head kata had not read before its intent
    notPerformedVerdicts,   \* the push observer's NOT PERFORMED verdicts
    landed,                 \* the push under the current intent reached the remote
    answered,               \* since that push landed, an observer read was answered
    badVerdict,             \* the push observer said NOT PERFORMED of a push that landed
    earlyUnclassified,      \* an unanswered read settled UNCLASSIFIED before MaxAsks
    beyondBoundCounted,     \* a listing the forge answered past its bound was counted as
                            \* an unanswered read
    markerDeleted,
    aba,                    \* after kata's push landed and before its observer's first
                            \* answer, the branch was back on the lease, by any path
                            \* (deleted, when the lease is its absence)
    faults

vars == <<reachable, head, prs, marked, crowded, up, read, looked, push, lease, pr, orphan,
          asks, wire, exported, pushes, creates, unintended, overUnread, notPerformedVerdicts,
          landed, answered, badVerdict, earlyUnclassified, beyondBoundCounted, markerDeleted,
          aba, faults>>

remote == <<reachable, head, prs, marked, crowded>>
ghosts == <<pushes, creates, unintended, overUnread, notPerformedVerdicts, landed, answered,
           badVerdict, earlyUnclassified, beyondBoundCounted, markerDeleted, aba>>

Init ==
    /\ reachable = TRUE /\ head = "none"
    /\ prs = [n \in PRs |-> "absent"] /\ marked = [n \in PRs |-> FALSE] /\ crowded = FALSE
    /\ up = TRUE /\ read = "unread" /\ looked = FALSE /\ push = "none" /\ lease = "any"
    /\ pr = "none" /\ orphan = [e \in {"push", "pr"} |-> FALSE] /\ asks = 0 /\ wire = "none"
    /\ exported = "running"
    /\ pushes = 0 /\ creates = 0 /\ unintended = FALSE /\ overUnread = FALSE
    /\ notPerformedVerdicts = 0 /\ landed = FALSE /\ answered = FALSE /\ badVerdict = FALSE
    /\ earlyUnclassified = FALSE /\ beyondBoundCounted = FALSE /\ markerDeleted = FALSE
    /\ aba = FALSE /\ faults = 0

Running == up /\ exported = "running"

-----------------------------------------------------------------------------
(* The export *)

\* `remote_branch_head` under a timeout; a failed read fails the export, no intent.
RemoteRead ==
    /\ Running /\ push = "none" /\ read = "unread" /\ MUTANT # "no_pre_intent_read"
    /\ IF reachable
       THEN read' = head /\ UNCHANGED exported
       ELSE exported' = "not_performed" /\ UNCHANGED read
    /\ UNCHANGED <<remote, up, looked, push, lease, pr, orphan, asks, wire, ghosts>>

\* The push intent: committed after the read, its answer the lease.
PushIntent ==
    /\ Running /\ push = "none" /\ MUTANT # "intent_after_push"
    /\ read # "unread" \/ MUTANT = "no_pre_intent_read"
    /\ push' = "intent"
    /\ lease' = IF MUTANT = "no_pre_intent_read" THEN "any" ELSE read
    /\ UNCHANGED <<remote, up, read, looked, pr, orphan, asks, wire, exported, ghosts>>

\* `git push --force-with-lease`: lands only on the leased head (the mutant's push
\* runs before its intent row, leased on its read). A push the remote refuses because
\* the branch moved off the lease records the command's error on its intent
\* (`record_forge_command_error`) and asks the push's observer (`observed_push`),
\* which judges it as it judges an intent a crash left.
Push ==
    /\ Running /\ reachable /\ wire = "none" /\ ~orphan["push"]
    /\ IF MUTANT = "intent_after_push" THEN push = "none" /\ read # "unread" ELSE push = "intent"
    /\ LET l == IF MUTANT = "intent_after_push" THEN read ELSE lease
           lands == l = "any" \/ head = l
       IN IF lands
          THEN /\ head' = "kata" /\ pushes' = pushes + 1
               /\ unintended' = (unintended \/ push # "intent")
               /\ overUnread' = (overUnread \/ (head \in {"other", "other2"} /\ read # head))
               /\ wire' = "push"
               /\ landed' = TRUE /\ answered' = FALSE
               /\ UNCHANGED <<exported, push, orphan>>
          ELSE IF push = "intent"
          THEN /\ push' = "failed" /\ orphan' = [orphan EXCEPT !["push"] = TRUE]
               /\ UNCHANGED <<exported, head, pushes, unintended, overUnread, wire, landed,
                              answered>>
          ELSE /\ exported' = "not_performed"  \* the mutant's push, before any intent
               /\ UNCHANGED <<push, orphan, head, pushes, unintended, overUnread, wire, landed,
                              answered>>
    /\ UNCHANGED <<reachable, prs, marked, crowded, up, read, looked, lease, pr, asks, creates,
                   notPerformedVerdicts, badVerdict, earlyUnclassified, beyondBoundCounted,
                   markerDeleted, aba>>

PushReceipt ==
    /\ up /\ wire = "push"
    /\ push' = "receipt" /\ wire' = "none"
    /\ UNCHANGED <<remote, up, read, looked, lease, pr, orphan, asks, exported, ghosts>>

\* `find_open_pr` under a timeout, before the pull request's intent: an open pull
\* request on kata's head is adopted under no intent; a lookup the forge does not
\* answer fails the export with no intent, the push standing (PROVEN NOT PERFORMED).
LookupPR ==
    /\ Running /\ push = "receipt" /\ pr = "none" /\ ~looked /\ wire = "none"
    /\ MUTANT # "no_pr_lookup"
    /\ IF ~reachable /\ MUTANT # "unread_lookup_is_none"
       THEN exported' = "pr_unread" /\ UNCHANGED looked
       ELSE IF reachable /\ \E n \in PRs : prs[n] = "open"
            THEN exported' = "done" /\ UNCHANGED looked
            ELSE looked' = TRUE /\ UNCHANGED exported
    /\ UNCHANGED <<remote, up, read, push, lease, pr, orphan, asks, wire, ghosts>>

PRIntent ==
    /\ Running /\ push = "receipt" /\ pr = "none" /\ wire = "none"
    /\ looked \/ MUTANT = "no_pr_lookup"
    /\ pr' = "intent" /\ looked' = FALSE
    /\ UNCHANGED <<remote, up, read, push, lease, orphan, asks, wire, exported, ghosts>>

\* `gh pr create`, the intent id as a marker in the body.
CreatePR ==
    /\ Running /\ reachable /\ pr = "intent" /\ wire = "none" /\ ~orphan["pr"]
    /\ \E n \in PRs :
         /\ prs[n] = "absent"
         /\ prs' = [prs EXCEPT ![n] = "open"]
         /\ marked' = [marked EXCEPT ![n] = TRUE]
    /\ creates' = creates + 1
    /\ wire' = "pr"
    /\ UNCHANGED <<reachable, head, crowded, up, read, looked, push, lease, pr, orphan, asks,
                   exported, pushes, unintended, overUnread, notPerformedVerdicts, landed,
                   answered, badVerdict, earlyUnclassified, beyondBoundCounted, markerDeleted,
                   aba>>

PRReceipt ==
    /\ up /\ wire = "pr"
    /\ pr' = "receipt" /\ wire' = "none" /\ exported' = "done"
    /\ UNCHANGED <<remote, up, read, looked, push, lease, orphan, asks, ghosts>>

-----------------------------------------------------------------------------
(* Recovery: an orphaned intent waits for its observer's verdict. *)

\* An observer read the remote did not answer: the intent stays open, its count of
\* unanswered reads one higher (`record_unanswered_forge_read`). Settling it at the
\* bound is SettleAtBound's, a step of its own. `kata run forge-reconcile` is one more
\* ask, like the sweep's.
Unanswered ==
    /\ asks' = asks + 1
    /\ IF MUTANT = "unread_is_unclassified"
       THEN /\ exported' = "unclassified"
            /\ earlyUnclassified' = (earlyUnclassified \/ asks + 1 < MaxAsks)
       ELSE UNCHANGED <<exported, earlyUnclassified>>

\* The intent's count reached the bound: it is settled UNCLASSIFIED
\* (`ExportDrive::settle_unanswered`), in the code's second transaction after the count's
\* — the same drive, or after a crash between the two, the next drive's pre-check.
SettleAtBound ==
    /\ Running /\ (orphan["push"] \/ orphan["pr"]) /\ asks >= MaxAsks
    /\ MUTANT # "unbounded_reask"
    /\ exported' = "unclassified"
    /\ UNCHANGED <<remote, up, read, looked, push, lease, pr, orphan, asks, wire, ghosts>>

\* The drive's pre-check (`ExportDrive::ask`): an intent counted MaxAsks times is not
\* asked; SettleAtBound settles it.
AskAllowed == asks < MaxAsks \/ MUTANT \in {"ask_at_bound", "unbounded_reask"}

\* The push's observer is the remote ref: our commit there, PUSHED; the lease still
\* there, NOT PERFORMED (start over from a fresh read, or, for a push whose command
\* failed, fail the export: nothing is pushed again); any other head (someone moved
\* the branch) contradicts both, `workspace_effect_unclassified` at once; a remote
\* that does not answer, Unanswered.
ObservePush ==
    /\ Running /\ orphan["push"] /\ AskAllowed
    /\ IF ~reachable /\ MUTANT # "unreachable_is_not_performed"
       THEN /\ Unanswered
            /\ UNCHANGED <<push, read, orphan, notPerformedVerdicts, landed, answered,
                           badVerdict>>
       ELSE IF reachable /\ head = "kata"
       THEN /\ push' = "receipt" /\ orphan' = [orphan EXCEPT !["push"] = FALSE]
            /\ asks' = 0 /\ answered' = TRUE
            /\ UNCHANGED <<exported, read, notPerformedVerdicts, landed, badVerdict,
                           earlyUnclassified>>
       ELSE IF ~reachable \/ head = lease \/ MUTANT = "naive_push_observer"
       THEN /\ push' = "none" /\ read' = "unread"
            /\ orphan' = [orphan EXCEPT !["push"] = FALSE] /\ asks' = 0
            /\ notPerformedVerdicts' = notPerformedVerdicts + 1
            /\ badVerdict' = (badVerdict \/ landed)
            /\ landed' = FALSE /\ answered' = FALSE
            /\ exported' = IF push = "failed" THEN "not_performed" ELSE exported
            /\ UNCHANGED earlyUnclassified
       ELSE IF MUTANT = "contradiction_reasked"
       THEN /\ Unanswered /\ answered' = TRUE
            /\ UNCHANGED <<push, read, orphan, notPerformedVerdicts, landed, badVerdict>>
       ELSE /\ exported' = "unclassified" /\ answered' = TRUE
            /\ UNCHANGED <<push, read, orphan, asks, notPerformedVerdicts, landed, badVerdict,
                           earlyUnclassified>>
    /\ UNCHANGED <<remote, up, looked, lease, pr, wire, pushes, creates, unintended, overUnread,
                   beyondBoundCounted, markerDeleted, aba>>

\* The PR's observer: a pull request carrying the marker, in any state. NOT PERFORMED
\* starts the pull request over: a fresh lookup, then a fresh intent. On a crowded
\* head the listing reaches its bound: the marked pull request is found only if it is
\* among those listed (either may hold), else the answer is BeyondBound — a state that
\* answers neither way, UNCLASSIFIED at once.
ObservePR ==
    /\ Running /\ orphan["pr"] /\ AskAllowed
    /\ \E listed \in BOOLEAN :
       LET seen == \E n \in PRs : marked[n] /\ (prs[n] = "open" \/
                                   (prs[n] = "closed" /\ MUTANT # "open_prs_only"))
           found == seen /\ (listed \/ ~crowded)
       IN IF ~reachable
          THEN /\ Unanswered
               /\ UNCHANGED <<pr, orphan, looked, beyondBoundCounted>>
          ELSE IF found
               THEN /\ pr' = "receipt" /\ exported' = "done"
                    /\ orphan' = [orphan EXCEPT !["pr"] = FALSE] /\ asks' = 0
                    /\ UNCHANGED <<looked, earlyUnclassified, beyondBoundCounted>>
               ELSE IF crowded /\ MUTANT = "beyond_bound_unanswered"
               THEN /\ Unanswered /\ beyondBoundCounted' = TRUE
                    /\ UNCHANGED <<pr, orphan, looked>>
               ELSE IF crowded
               THEN /\ exported' = "unclassified"
                    /\ UNCHANGED <<pr, orphan, looked, asks, earlyUnclassified,
                                   beyondBoundCounted>>
               ELSE /\ pr' = "none" /\ looked' = FALSE  \* not performed
                    /\ orphan' = [orphan EXCEPT !["pr"] = FALSE] /\ asks' = 0
                    /\ UNCHANGED <<exported, earlyUnclassified, beyondBoundCounted>>
    /\ UNCHANGED <<remote, up, read, push, lease, wire, pushes, creates, unintended, overUnread,
                   notPerformedVerdicts, landed, answered, badVerdict, markerDeleted, aba>>

\* The mutant: an orphaned intent's effect is simply sent again.
BlindRedo ==
    /\ MUTANT = "redo_without_verdict" /\ Running /\ reachable /\ orphan["push"]
    /\ head' = "kata" /\ pushes' = pushes + 1
    /\ push' = "receipt" /\ orphan' = [orphan EXCEPT !["push"] = FALSE]
    /\ UNCHANGED <<reachable, prs, marked, crowded, up, read, looked, lease, pr, asks, wire,
                   exported, creates, unintended, overUnread, notPerformedVerdicts, landed,
                   answered, badVerdict, earlyUnclassified, beyondBoundCounted, markerDeleted,
                   aba>>

-----------------------------------------------------------------------------
(* Faults and the world *)

\* kata-control dies: memory is gone; a landed effect's receipt is not written, and
\* every intent without a receipt is owed a verdict.
Crash ==
    /\ up
    /\ up' = FALSE /\ read' = "unread" /\ looked' = FALSE /\ wire' = "none"
    /\ orphan' = [orphan EXCEPT !["push"] = push \in {"intent", "failed"}, !["pr"] = pr = "intent"]
    /\ UNCHANGED <<remote, push, lease, pr, asks, exported, ghosts>>

Restart ==
    /\ ~up /\ up' = TRUE
    /\ UNCHANGED <<remote, read, looked, push, lease, pr, orphan, asks, wire, exported, ghosts>>

RemoteDown ==
    /\ reachable /\ reachable' = FALSE
    /\ UNCHANGED <<head, prs, marked, crowded, up, read, looked, push, lease, pr, orphan, asks, wire,
                   exported, ghosts>>

RemoteUp ==
    /\ ~reachable /\ reachable' = TRUE
    /\ UNCHANGED <<head, prs, marked, crowded, up, read, looked, push, lease, pr, orphan, asks, wire,
                   exported, ghosts>>

\* Someone else pushes to the branch or deletes it ("none"). Back on the lease after
\* kata's push landed and before its observer's first answer, by any path, is ABA: a
\* deletion of a branch kata found absent, or a push over someone else's that restores
\* the leased head, included.
OtherPush ==
    /\ \E v \in {"other", "other2", "none"} :
         /\ v # head /\ head' = v
         /\ aba' = (aba \/ (landed /\ ~answered /\ v = lease))
    /\ UNCHANGED <<reachable, prs, marked, crowded, up, read, looked, push, lease, pr, orphan,
                   asks, wire, exported, pushes, creates, unintended, overUnread,
                   notPerformedVerdicts, landed, answered, badVerdict, earlyUnclassified,
                   beyondBoundCounted, markerDeleted>>

OtherClosesPR ==
    /\ \E n \in PRs : prs[n] = "open" /\ prs' = [prs EXCEPT ![n] = "closed"]
    /\ UNCHANGED <<reachable, head, marked, crowded, up, read, looked, push, lease, pr, orphan, asks,
                   wire, exported, ghosts>>

\* The stated residual: a human deletes the marker.
DeleteMarker ==
    /\ \E n \in PRs : marked[n] /\ marked' = [marked EXCEPT ![n] = FALSE]
    /\ markerDeleted' = TRUE
    /\ UNCHANGED <<reachable, head, prs, crowded, up, read, looked, push, lease, pr, orphan,
                   asks, wire, exported, pushes, creates, unintended, overUnread,
                   notPerformedVerdicts, landed, answered, badVerdict, earlyUnclassified,
                   beyondBoundCounted, aba>>

\* Someone else opens and closes more pull requests on kata's head than the marker
\* listing reads (none carries the marker, none is open for the lookup to adopt; the
\* listing past its bound is what the model keeps of them).
OtherCrowdsHead ==
    /\ ~crowded /\ crowded' = TRUE
    /\ UNCHANGED <<reachable, head, prs, marked, up, read, looked, push, lease, pr, orphan,
                   asks, wire, exported, ghosts>>

Fault == Crash \/ RemoteDown \/ OtherPush \/ OtherClosesPR \/ DeleteMarker \/ OtherCrowdsHead

Step ==
    \/ RemoteRead \/ PushIntent \/ Push \/ PushReceipt \/ LookupPR \/ PRIntent \/ CreatePR
    \/ PRReceipt \/ ObservePush \/ ObservePR \/ SettleAtBound \/ BlindRedo \/ Restart
    \/ RemoteUp

Next ==
    \/ faults < MaxFaults /\ Fault /\ faults' = faults + 1
    \/ Step /\ UNCHANGED faults

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Invariants *)

\* Plan M0: no forge wire effect without its intent.
NoWireEffectWithoutIntent == ~unintended

\* The push replaces only the head kata read before its intent.
NoPushOverUnreadHead == ~overUnread

\* A push repeats only after its observer said the earlier one was not performed (the
\* verdict's soundness is ObserverVerdictSound's).
NoPushWithoutVerdict == pushes <= 1 + notPerformedVerdicts

\* One pull request; the stated residual excepted: a pull request whose marker was
\* deleted and that is no longer open (an open one is adopted by the lookup).
OnePullRequest == creates <= 1 \/ \E n \in PRs : prs[n] = "closed" /\ ~marked[n]

\* The push observer says NOT PERFORMED only of a push that did not land (outside the
\* ABA residual when EXCUSE_ABA).
ObserverVerdictSound == ~badVerdict \/ (EXCUSE_ABA /\ aba)

\* PROVEN NOT PERFORMED only when the remote holds nothing of the export.
NotPerformedIsSound == exported = "not_performed" => head # "kata" /\ creates = 0

\* A read the remote did not answer settles nothing before the bound.
NoUnclassifiedBeforeTheBound == ~earlyUnclassified

\* An open intent is asked at most MaxAsks times without an answer.
NoAskPastTheBound == asks <= MaxAsks

\* A listing the forge answered past its bound is UNCLASSIFIED at once, never counted
\* as a read the forge did not answer.
BeyondBoundSettlesAtOnce == ~beyondBoundCounted

=============================================================================
