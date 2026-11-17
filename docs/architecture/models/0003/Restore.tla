------------------------------- MODULE Restore -------------------------------
(***************************************************************************)
(* ADR 0003 §2 (identity, data generations, revocations that do not roll  *)
(* back) and §10 (backup and restore) as a checked model.                  *)
(*                                                                         *)
(* kata-control's admission registry (admission.db: a monotonic sequence,  *)
(* admitted keys, revocations) is snapshotted with its stores into a local *)
(* spool and shipped off-host by a host unit. The gateway mirrors the      *)
(* registry in its own identity directory, pushed over its session with    *)
(* kata-control. A restore mints a new data generation. With the gateway   *)
(* still pinned it waits for the gateway's answer and adopts its mirror    *)
(* when the mirror's sequence is newer than the backup's, before it        *)
(* accepts any Hello; with no mirror (a new machine, a lost gateway        *)
(* identity) it drops every admitted key, an admission.db write that       *)
(* advances the monotonic sequence like any other. It holds every          *)
(* execution open at the backup's point and every schedule catch-up due    *)
(* after it for the operator, and settles the attempts open in the         *)
(* restored store only after W from boot (§4: a restore is a boot).        *)
(*                                                                         *)
(* One execution with one stage that runs in a capsule and performs one    *)
(* external effect per capsule, and one schedule slot whose run performs   *)
(* one. A capsule dispatched by a generation that is gone gets no grant:   *)
(* its provider kills it within LK = L + K. Time is relative.              *)
(*                                                                         *)
(* REVOKE_ACK: when `kata node revoke` reports success. "commit" is ADR    *)
(* 0003 as written (`revoked` committed in admission.db); "mirror" is      *)
(* after the gateway's mirror holds it (F4's correction). WRITES_WAIT:     *)
(* TRUE holds every admission write of a restored control plane until the  *)
(* gateway answers (F6's correction); FALSE holds only Hello, as written.  *)
(* RESUME_AFTER_W: TRUE holds every dispatch of a restored control plane,  *)
(* an operator's resume included, until W from boot (F5's correction);     *)
(* FALSE is the ADR as written.                                            *)
(*                                                                         *)
(* ASSUMED, from ADR §3: `kata-node join <token>` mints the node's key, so *)
(* a key is admitted at most once ever; a revoked key never rejoins.       *)
(* ASSUMED, unstated in the ADR (each has the mutant that drops it): the   *)
(* no-mirror drop advances the sequence (drop_without_seq_bump); a         *)
(* restored kata-control settles the restored store's open attempts only   *)
(* after W from boot (restore_settles_at_boot); and it refuses `Resume` of *)
(* an incarnation an older generation welcomed, so an older generation's   *)
(* capsule gets no further grant (resume_across_restore).                  *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Keys,           \* node keys
    LK,             \* L + K: last grant to an empty subtree, real units
    W,              \* the restart wait, real units (W > LK)
    REVOKE_ACK,     \* "commit" | "mirror"
    WRITES_WAIT,    \* admission writes wait for the gateway's answer after a restore
    RESUME_AFTER_W, \* see above
    WORK,           \* FALSE: no work runs (an admission-only check; Keys = {} for work-only)
    ALLOW_SERVER_LOSS, ALLOW_DATA_LOSS, ALLOW_LINK_LOSS,
    MaxFaults,
    MUTANT

Mutants == {"none",
            "no_mirror_adopt",          \* the restore keeps the backup's registry
            "hello_before_adoption",    \* Hello accepted before the gateway answered
            "keep_keys_without_mirror", \* no mirror, yet the backup's admitted keys stay
            "drop_without_seq_bump",    \* the no-mirror drop leaves the sequence where it was
            "no_hold",                  \* executions open at the backup's point dispatch
            "no_schedule_hold",         \* a catch-up due after the backup fires
            "restore_settles_at_boot",  \* attempts open in the backup settle at boot
            "orphan_never_killed",      \* no provider kill at an orphan's lease deadline
            "resume_across_restore"}    \* a restored control plane accepts an older
                                        \* generation's Resume and grants its capsule

ASSUME MUTANT \in Mutants /\ REVOKE_ACK \in {"commit", "mirror"} /\ W > LK

Gens == 1 .. (1 + MaxFaults)
NoReg == [seq |-> 0, admitted |-> {}, revoked |-> {}]
Work == {"exec", "slot"}
NoCap == [run |-> FALSE, lease |-> -1, fx |-> FALSE]
NoSnap == [ok |-> FALSE, reg |-> NoReg, work |-> [w \in Work |-> "absent"],
           att |-> [st |-> "none", gen |-> 0]]

VARIABLES
    \* ---- kata-control ----
    cUp,
    dataLost,     \* the data directory is gone; a restore is the way back
    gen,          \* data generation
    reg,          \* admission registry
    adoptPending, \* restored with the gateway pinned: Hello waits for its answer
    bootAge,      \* real time since boot, capped at W
    work,         \* [Work -> "absent"|"open"|"held"|"running"|"done"] durable rows
    att,          \* the execution's attempt row: [st: "none"|"dispatched"|"settled", gen]
    \* ---- gateway identity ----
    mirror,       \* the gateway's mirror registry
    hasMirror,    \* FALSE once the gateway's identity is lost (a new machine)
    link,         \* gateway <-> kata-control session
    \* ---- backup ----
    spool,        \* the latest local snapshot (NoSnap: none)
    offhost,      \* the latest shipped snapshot (NoSnap: none)
    \* ---- nodes ----
    caps,         \* [Gens -> capsule of the execution's stage dispatched by that generation]
    \* ---- ghosts ----
    joined,       \* keys ever admitted: `kata-node join` mints its key, so none rejoins
    acked,        \* revocations reported to the operator as done
    welcomedRevoked, \* a key the operator was told is revoked was welcomed
    effects,      \* [Work -> Nat] external effects performed
    resumed,      \* [Work -> Nat] operator resumes
    faults

vars == <<cUp, dataLost, gen, reg, adoptPending, bootAge, work, att, mirror, hasMirror, link,
          spool, offhost, caps, joined, acked, welcomedRevoked, effects, resumed, faults>>

Init ==
    /\ cUp = TRUE
    /\ dataLost = FALSE
    /\ gen = 1
    /\ reg = NoReg
    /\ adoptPending = FALSE
    /\ bootAge = W
    /\ work = [w \in Work |-> IF w = "exec" THEN "open" ELSE "absent"]
    /\ att = [st |-> "none", gen |-> 0]
    /\ mirror = NoReg
    /\ hasMirror = TRUE
    /\ link = TRUE
    /\ spool = NoSnap
    /\ offhost = NoSnap
    /\ caps = [g \in Gens |-> NoCap]
    /\ joined = {}
    /\ acked = {}
    /\ welcomedRevoked = FALSE
    /\ effects = [w \in Work |-> 0]
    /\ resumed = [w \in Work |-> 0]
    /\ faults = 0

Down(x) == IF x > 0 THEN x - 1 ELSE x
Min(a, b) == IF a < b THEN a ELSE b

\* A capsule whose dispatching generation is not the live one gets no grant: a restored
\* kata-control refuses its node's `Resume` (the mutant accepts it).
Orphan(g) == ~cUp \/ (g # gen /\ MUTANT # "resume_across_restore")

-----------------------------------------------------------------------------
(* Time *)

\* The provider kills at its lease deadline: no capsule outlives LK past its last grant,
\* and the last grant is no later than the moment its generation stopped granting.
Tick ==
    /\ MUTANT # "orphan_never_killed" =>
         \A g \in Gens : caps[g].run =>
           /\ Orphan(g) => caps[g].lease # -1
           /\ caps[g].lease # 0
    /\ bootAge' = Min(bootAge + 1, W)
    /\ caps' = [g \in Gens |-> [caps[g] EXCEPT !.lease = Down(@)]]
    /\ UNCHANGED <<cUp, dataLost, gen, reg, adoptPending, work, att, mirror, hasMirror, link, spool,
                   offhost, joined, acked, welcomedRevoked, effects, resumed>>

-----------------------------------------------------------------------------
(* Admission *)

\* `kata node token create` + `kata-node join`: a key is admitted. The join mints the
\* node's key, so a key is admitted at most once, ever.
Join(k) ==
    /\ cUp /\ k \notin joined
    /\ WRITES_WAIT => ~adoptPending
    /\ joined' = joined \cup {k}
    /\ reg' = [reg EXCEPT !.seq = @ + 1, !.admitted = @ \cup {k}]
    /\ UNCHANGED <<cUp, dataLost, gen, adoptPending, bootAge, work, att, mirror, hasMirror, link,
                   spool, offhost, caps, acked, welcomedRevoked, effects, resumed>>

\* `kata node revoke`: `revoked` commits first.
Revoke(k) ==
    /\ cUp /\ k \in reg.admitted /\ k \notin reg.revoked
    /\ WRITES_WAIT => ~adoptPending
    /\ reg' = [reg EXCEPT !.seq = @ + 1, !.revoked = @ \cup {k}]
    /\ acked' = IF REVOKE_ACK = "commit" THEN acked \cup {k} ELSE acked
    /\ UNCHANGED <<joined, cUp, dataLost, gen, adoptPending, bootAge, work, att, mirror, hasMirror, link,
                   spool, offhost, caps, welcomedRevoked, effects, resumed>>

\* The gateway's session carries the registry into its mirror.
MirrorSync ==
    /\ cUp /\ link /\ ~adoptPending /\ hasMirror /\ reg.seq > mirror.seq
    /\ mirror' = reg
    /\ acked' = IF REVOKE_ACK = "mirror" THEN acked \cup reg.revoked ELSE acked
    /\ UNCHANGED <<joined, cUp, dataLost, gen, reg, adoptPending, bootAge, work, att, hasMirror, link, spool,
                   offhost, caps, welcomedRevoked, effects, resumed>>

\* The gateway answers the restored registry with its mirror: a registry whose sequence
\* is older than the mirror's is `admission_rolled_back`, and kata-control commits the
\* mirror in its place (ADR §2).
GatewayAnswers ==
    /\ cUp /\ link /\ adoptPending
    /\ reg' = IF mirror.seq > reg.seq /\ MUTANT # "no_mirror_adopt" THEN mirror ELSE reg
    /\ adoptPending' = FALSE
    /\ UNCHANGED <<cUp, dataLost, gen, bootAge, work, att, mirror, hasMirror, link, spool, offhost,
                   caps, joined, acked, welcomedRevoked, effects, resumed>>

\* A node presents its key: welcomed only if admitted and not revoked, and only once the
\* restored registry has the gateway's answer.
Hello(k) ==
    /\ cUp /\ k \in reg.admitted /\ k \notin reg.revoked
    /\ ~adoptPending \/ MUTANT = "hello_before_adoption"
    /\ welcomedRevoked' = (welcomedRevoked \/ k \in acked)
    /\ UNCHANGED <<cUp, dataLost, gen, reg, adoptPending, bootAge, work, att, mirror, hasMirror, link,
                   spool, offhost, caps, joined, acked, effects, resumed>>

-----------------------------------------------------------------------------
(* Work *)

Dispatch ==
    /\ WORK /\ cUp /\ work["exec"] = "open" /\ att.st = "none"
    /\ RESUME_AFTER_W => bootAge >= W
    /\ att' = [st |-> "dispatched", gen |-> gen]
    /\ work' = [work EXCEPT !["exec"] = "running"]
    /\ caps' = [caps EXCEPT ![gen] = [run |-> TRUE, lease |-> -1, fx |-> FALSE]]
    /\ UNCHANGED <<cUp, dataLost, gen, reg, adoptPending, bootAge, mirror, hasMirror, link, spool,
                   offhost, joined, acked, welcomedRevoked, effects, resumed>>

\* The capsule's external effect: a push, a model request that delivered output.
CapsuleEffect(g) ==
    /\ caps[g].run /\ ~caps[g].fx
    /\ caps' = [caps EXCEPT ![g].fx = TRUE]
    /\ effects' = [effects EXCEPT !["exec"] = @ + 1]
    /\ UNCHANGED <<cUp, dataLost, gen, reg, adoptPending, bootAge, work, att, mirror, hasMirror, link,
                   spool, offhost, joined, acked, welcomedRevoked, resumed>>

\* The capsule ends and its node reports to the generation that dispatched it.
CapsuleDone ==
    /\ cUp /\ caps[gen].run /\ att = [st |-> "dispatched", gen |-> gen]
    /\ caps' = [caps EXCEPT ![gen].run = FALSE]
    /\ att' = [att EXCEPT !.st = "settled"]
    /\ work' = [work EXCEPT !["exec"] = "done"]
    /\ UNCHANGED <<cUp, dataLost, gen, reg, adoptPending, bootAge, mirror, hasMirror, link, spool,
                   offhost, joined, acked, welcomedRevoked, effects, resumed>>

\* An orphaned capsule's lease runs out from its last grant: no later than now.
LeaseStops(g) ==
    /\ MUTANT # "orphan_never_killed"
    /\ caps[g].run /\ caps[g].lease = -1 /\ Orphan(g)
    /\ caps' = [caps EXCEPT ![g].lease = LK]
    /\ UNCHANGED <<cUp, dataLost, gen, reg, adoptPending, bootAge, work, att, mirror, hasMirror, link,
                   spool, offhost, joined, acked, welcomedRevoked, effects, resumed>>

\* The provider (or the node, refused at Resume) kills it at or before its deadline.
ProviderKill(g) ==
    /\ caps[g].run /\ caps[g].lease # -1
    /\ caps' = [caps EXCEPT ![g].run = FALSE]
    /\ UNCHANGED <<cUp, dataLost, gen, reg, adoptPending, bootAge, work, att, mirror, hasMirror, link,
                   spool, offhost, joined, acked, welcomedRevoked, effects, resumed>>

\* The schedule slot comes due and its run performs its effect.
SlotFires ==
    /\ WORK /\ cUp /\ work["slot"] = "absent"
    /\ RESUME_AFTER_W => bootAge >= W
    /\ work' = [work EXCEPT !["slot"] = "done"]
    /\ effects' = [effects EXCEPT !["slot"] = @ + 1]
    /\ UNCHANGED <<cUp, dataLost, gen, reg, adoptPending, bootAge, att, mirror, hasMirror, link, spool,
                   offhost, caps, joined, acked, welcomedRevoked, resumed>>

\* An attempt open in the restored store settles PROVEN AMBIGUOUS after W from boot.
SettleRestored ==
    /\ cUp /\ att.st = "dispatched" /\ att.gen # gen
    /\ MUTANT = "restore_settles_at_boot" \/ bootAge >= W
    /\ att' = [att EXCEPT !.st = "settled"]
    /\ UNCHANGED <<cUp, dataLost, gen, reg, adoptPending, bootAge, work, mirror, hasMirror, link,
                   spool, offhost, caps, joined, acked, welcomedRevoked, effects, resumed>>

\* The operator resumes held work: it may run again, knowingly.
OperatorResume(w) ==
    /\ cUp /\ work[w] = "held"
    /\ w = "exec" => att.st # "dispatched"
    /\ resumed' = [resumed EXCEPT ![w] = @ + 1]
    /\ work' = [work EXCEPT ![w] = IF w = "exec" THEN "open" ELSE "absent"]
    /\ att' = IF w = "exec" THEN [st |-> "none", gen |-> 0] ELSE att
    /\ UNCHANGED <<cUp, dataLost, gen, reg, adoptPending, bootAge, mirror, hasMirror, link, spool,
                   offhost, caps, joined, acked, welcomedRevoked, effects>>

-----------------------------------------------------------------------------
(* Backup and restore *)

Backup ==
    /\ cUp /\ ~adoptPending
    /\ spool' = [ok |-> TRUE, reg |-> reg, work |-> work, att |-> att]
    /\ UNCHANGED <<cUp, dataLost, gen, reg, adoptPending, bootAge, work, att, mirror, hasMirror, link,
                   offhost, caps, joined, acked, welcomedRevoked, effects, resumed>>

Ship ==
    /\ spool.ok /\ offhost # spool
    /\ offhost' = spool
    /\ UNCHANGED <<cUp, dataLost, gen, reg, adoptPending, bootAge, work, att, mirror, hasMirror, link,
                   spool, caps, joined, acked, welcomedRevoked, effects, resumed>>

\* kata-control's data directory is lost (its spool with it); the gateway's identity
\* directory survives.
DataLoss ==
    /\ ALLOW_DATA_LOSS /\ cUp
    /\ cUp' = FALSE
    /\ dataLost' = TRUE
    /\ spool' = NoSnap
    /\ UNCHANGED <<gen, reg, adoptPending, bootAge, work, att, mirror, hasMirror, link, offhost, caps,
                   joined, acked, welcomedRevoked, effects, resumed>>

\* The server is lost: kata-control's data, its spool, and the gateway's identity.
ServerLoss ==
    /\ ALLOW_SERVER_LOSS /\ cUp
    /\ cUp' = FALSE
    /\ dataLost' = TRUE
    /\ spool' = NoSnap
    /\ hasMirror' = FALSE
    /\ UNCHANGED <<gen, reg, adoptPending, bootAge, work, att, mirror, link, offhost, caps,
                   joined, acked, welcomedRevoked, effects, resumed>>

LinkDown ==
    /\ ALLOW_LINK_LOSS /\ link
    /\ link' = FALSE
    /\ UNCHANGED <<cUp, dataLost, gen, reg, adoptPending, bootAge, work, att, mirror, hasMirror,
                   spool, offhost, caps, joined, acked, welcomedRevoked, effects, resumed>>

LinkUp ==
    /\ ~link
    /\ link' = TRUE
    /\ UNCHANGED <<cUp, dataLost, gen, reg, adoptPending, bootAge, work, att, mirror, hasMirror,
                   spool, offhost, caps, joined, acked, welcomedRevoked, effects, resumed>>

\* Restore from the latest shipped snapshot: a new generation; with no mirror every
\* admitted key dropped, an admission.db write that advances the sequence (and a new
\* gateway registers with the restored registry as its mirror), else the gateway's
\* answer awaited before any Hello; held work as ADR §10 says.
Restore ==
    /\ ~cUp /\ dataLost /\ offhost.ok /\ gen < 1 + MaxFaults
    /\ LET b == offhost.reg IN
       IF ~hasMirror
       THEN /\ reg' = CASE MUTANT = "keep_keys_without_mirror" -> b
                       [] MUTANT = "drop_without_seq_bump" -> [b EXCEPT !.admitted = {}]
                       [] OTHER -> [b EXCEPT !.admitted = {}, !.seq = @ + 1]
            /\ adoptPending' = FALSE
            \* A new gateway registers; its mirror starts from the restored registry.
            /\ mirror' = reg'
            /\ hasMirror' = TRUE
       ELSE /\ reg' = b
            /\ adoptPending' = TRUE
            /\ UNCHANGED <<mirror, hasMirror>>
    /\ work' = [w \in Work |->
                  CASE offhost.work[w] \in {"open", "running"} ->
                         IF MUTANT = "no_hold" THEN "open" ELSE "held"
                    [] w = "slot" /\ offhost.work[w] = "absent" ->
                         IF MUTANT = "no_schedule_hold" THEN "absent" ELSE "held"
                    [] OTHER -> offhost.work[w]]
    /\ att' = offhost.att
    /\ gen' = gen + 1
    /\ cUp' = TRUE
    /\ dataLost' = FALSE
    /\ bootAge' = 0
    /\ UNCHANGED <<link, spool, offhost, caps, joined, acked, welcomedRevoked, effects, resumed>>

-----------------------------------------------------------------------------

Fault == DataLoss \/ ServerLoss \/ LinkDown

Step ==
    \/ Tick \/ MirrorSync \/ GatewayAnswers \/ Dispatch \/ CapsuleDone \/ SlotFires
    \/ SettleRestored \/ Backup \/ Ship \/ LinkUp \/ Restore
    \/ \E k \in Keys : Join(k) \/ Revoke(k) \/ Hello(k)
    \/ \E g \in Gens : CapsuleEffect(g) \/ LeaseStops(g) \/ ProviderKill(g)
    \/ \E w \in Work : OperatorResume(w)

Next ==
    \/ faults < MaxFaults /\ Fault /\ faults' = faults + 1
    \/ Step /\ UNCHANGED faults

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Invariants *)

\* ADR §2, decision 7: revocations do not roll back. A key the operator was told is
\* revoked is never welcomed again, a restore included.
RevokedNeverWelcomed == ~welcomedRevoked

\* ADR §10: no automatic re-run after a possible external effect, a restore included:
\* an effect repeats only when the operator resumed the work.
NoRepeatWithoutOperator == \A w \in Work : effects[w] <= 1 + resumed[w]

\* ADR §4 across a restore: no capsule runs after its attempt is settled.
NoCapsuleAfterSettlement == ~(att.st = "settled" /\ att.gen \in Gens /\ caps[att.gen].run)

\* The stage never runs in two capsules at once, across a restore too.
OneCapsulePerStage == \A g, h \in Gens : (g # h /\ caps[g].run) => ~caps[h].run

=============================================================================
