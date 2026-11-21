------------------------------ MODULE BridgeFull ------------------------------
(***************************************************************************)
(* Typed single-session version of BridgeContract.tla for Apalache         *)
(* (inductive checking), grown from BridgeSlice.tla one feature group at a *)
(* time.  The invariants of BridgeContract.tla are all per session, and    *)
(* sessions interact only through the global Tick, so one session carries  *)
(* them; multi-session behaviour is not claimed.  Dropped on purpose: the  *)
(* model bounds MaxEvents and MaxRestarts (the event count n is unbounded  *)
(* here) and the hash chain (not modelled anywhere).  A record is updated  *)
(* by EXCEPT because Apalache does not type the record merge (@@).         *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, Apalache

\* @typeAlias: sig = { by: Str, nonce: Int, pre: Str };
\* @typeAlias: rec = { att: Str, hum: Str, life: Str, n: Int, K: Set(Str),
\*   C: Set(Str), rk: Str, rev: Set(Str), hard: Set(Str), recorded: Bool,
\*   nid: Int, nb: Int -> Int, nu: Set(Int), uf: Int, obs: Set($sig),
\*   detLeft: Int, humLeft: Int, totLeft: Int, endWhy: Str,
\*   scope: Set(Str), ver: Int, queue: Set(Str), callLeft: Str -> Int,
\*   used: Set(Str), ans: Str -> Str, apprLeft: Int, drained: Set(Str),
\*   held: Set(Str), opd: Set(Str), dlv: Set(Str), sent: Set(Str),
\*   fwd: Set(Str), quar: Bool, corrupt: Bool };
\* @typeAlias: lst = { auth: Bool, live: Bool, pre: Str, known: Bool,
\*   rec: Bool, src: Str };
BF_aliases == TRUE

CONSTANTS
    \* @type: Set(Str);
    Clients,
    \* @type: Set(Str);
    AdvKeys,
    \* @type: Bool;
    AttackOn,
    \* @type: Int;
    ObsMax,
    \* @type: Int;
    LiveLimit,
    \* @type: Int;
    FailMax,
    \* @type: Int;
    TDetach,
    \* @type: Int;
    THuman,
    \* @type: Int;
    TNonce,
    \* @type: Int;
    TTotal,
    \* @type: Str;
    DetPolicy,
    \* @type: Set(Str);
    Allow,
    \* @type: Int;
    TCall,
    \* @type: Int;
    TApprove,
    \* @type: Int;
    QMax,
    \* @type: Bool;
    AllowFaults

MaxNonce == 3
Keys == {"k1", "k2"}
Perms == {"p1", "p2"}
MaxVer == 2

CInit ==
    /\ Clients = {"c1", "c2", "c3"} /\ AdvKeys = {"x", "y"}
    /\ AttackOn = TRUE /\ ObsMax \in 0..3 /\ LiveLimit \in 1..3 /\ FailMax \in 1..3
    /\ TDetach \in 1..5 /\ THuman \in 1..5 /\ TNonce \in 1..5 /\ TTotal \in 5..8
    /\ TDetach <= TTotal
    /\ DetPolicy \in {"refuse", "queue", "forward"}
    /\ Allow \in {{}, {"p1"}, {"p2"}, {"p1", "p2"}}
    /\ TCall \in 1..5 /\ TCall <= THuman /\ TApprove \in 1..5 /\ QMax \in 1..2
    /\ AllowFaults \in BOOLEAN

\* The permission a queued call needs (calls are "k1" and "k2").
\* @type: Str => Str;
Need(k) == IF k = "k1" THEN "p1" ELSE "p2"

VARIABLES
    \* @type: $rec;
    ss,
    \* @type: $rec;
    prv,         \* ghost: the record before the last step (for step properties)
    \* @type: $lst;
    last         \* ghost: the last presentation

vars == <<ss, prv, last>>

NoTimer == -1

InitRec == [ att |-> "Att", hum |-> "None", life |-> "Active", n |-> 1,
             K |-> {"c1"}, C |-> {"c1"}, rk |-> "none",
             rev |-> {}, hard |-> {}, recorded |-> FALSE,
             nid |-> 0, nb |-> [i \in 1..MaxNonce |-> NoTimer], nu |-> {},
             uf |-> 0, obs |-> {}, detLeft |-> NoTimer, humLeft |-> NoTimer,
             totLeft |-> TTotal, endWhy |-> "none",
             scope |-> Perms, ver |-> 0, queue |-> {},
             callLeft |-> [k \in Keys |-> NoTimer], used |-> {},
             ans |-> [k \in Keys |-> "none"], apprLeft |-> 0, drained |-> {},
             held |-> {}, opd |-> {}, dlv |-> {}, sent |-> {}, fwd |-> {},
             quar |-> FALSE, corrupt |-> FALSE ]

InitLast == [auth |-> FALSE, live |-> FALSE, pre |-> "none", known |-> FALSE,
             rec |-> TRUE, src |-> "honest"]

Init == ss = InitRec /\ prv = InitRec /\ last = InitLast

\* @type: $rec => Bool;
ExhR(r) == r.K /= {} /\ r.K \subseteq r.rev

Live == ss.life = "Active" /\ ~ss.quar
Active == Live /\ ~ExhR(ss)
\* @type: $rec => Set(Int);
LiveSet(r) == {i \in 1..MaxNonce : i <= r.nid /\ r.nb[i] > 0 /\ i \notin r.nu}

\* @type: (Str, $sig, Int, Str) => Bool;
Verifies(key, sg, claimed, pre) ==
    sg.by = key /\ sg.nonce = claimed /\ sg.pre = pre

(***************************************************************************)
(* Actions (each leaves last unchanged unless it is a presentation)        *)
(***************************************************************************)

\* @type: Str => Bool;
Disconnect(c) ==
    /\ Live
    /\ \/ ss.att = "Att" /\ c \in ss.C /\ ss.C /= {c}
          /\ ss' = [ss EXCEPT !.n = @ + 1, !.C = @ \ {c}]
       \/ ss.att = "Att" /\ ss.C = {c}
          /\ ss' = [ss EXCEPT !.n = @ + 2, !.att = "Det", !.C = {},
                    !.detLeft = TDetach, !.recorded = TRUE]
       \/ ss.att = "Res" /\ ss.rk = c
          /\ ss' = [ss EXCEPT !.n = @ + 2, !.att = "Det", !.rk = "none",
                    !.detLeft = TDetach, !.recorded = TRUE]
    /\ last' = last

Escalate ==
    /\ Active
    /\ ss' = [ss EXCEPT !.n = @ + 1, !.hum = "Pend",
              !.humLeft = IF ss.hum = "None" THEN THuman ELSE @]
    /\ last' = last

Resolve ==
    /\ Active /\ ss.hum = "Pend"
    /\ ss' = [ss EXCEPT !.n = @ + 1, !.hum = "None", !.humLeft = NoTimer,
              !.apprLeft = TApprove]
    /\ last' = last

\* I2, I13: a call arriving while Human = Pend is queued, or rejected when full.
\* @type: Str => Bool;
Submit(k) ==
    /\ Active /\ ss.hum = "Pend" /\ k \notin ss.used
    /\ IF Cardinality(ss.queue) < QMax
       THEN ss' = [ss EXCEPT !.n = @ + 1, !.queue = @ \cup {k},
                   !.callLeft[k] = TCall, !.used = @ \cup {k}]
       ELSE ss' = [ss EXCEPT !.n = @ + 1, !.used = @ \cup {k}]
    /\ last' = last

\* I13: a queued call outlives T_call: TOOL_CALL_EXPIRED.
\* @type: Str => Bool;
ExpireCall(k) ==
    /\ Active /\ k \in ss.queue /\ ss.callLeft[k] = 0
    /\ ss' = [ss EXCEPT !.n = @ + 1, !.queue = @ \ {k}, !.held = @ \ {k},
              !.callLeft[k] = NoTimer, !.ans[k] = "none"]
    /\ last' = last

\* I14: the human answers a queued call; the first answer is final.
\* @type: (Str, Str) => Bool;
Answer(k, a) ==
    /\ Active /\ k \in ss.queue /\ ss.ans[k] = "none"
    /\ ss' = [ss EXCEPT !.n = @ + 1, !.ans[k] = a]
    /\ last' = last

\* G1: a call arrives with h = None while no client is attached.
\* @type: Str => Bool;
SubmitAway(k) ==
    /\ DetPolicy /= "refuse"
    /\ Active /\ ss.hum = "None" /\ ss.att /= "Att"
    /\ k \notin ss.used /\ Need(k) \in ss.scope
    /\ IF DetPolicy = "queue"
       THEN IF Cardinality(ss.queue) < QMax
            THEN ss' = [ss EXCEPT !.n = @ + 1, !.queue = @ \cup {k},
                        !.held = @ \cup {k}, !.callLeft[k] = TCall,
                        !.used = @ \cup {k}]
            ELSE ss' = [ss EXCEPT !.n = @ + 1, !.used = @ \cup {k}]
       ELSE /\ Need(k) \in Allow
            /\ ss' = [ss EXCEPT !.n = @ + 3, !.drained = @ \cup {k},
                      !.opd = @ \cup {k}, !.used = @ \cup {k}]
    /\ last' = last

\* Rule D + I13 + I14: drain in (Att, None), revalidating each call.
Drain ==
    /\ Active /\ ss.att = "Att" /\ ss.hum = "None" /\ ss.queue /= {}
    /\ LET r == ss
           wait == {k \in r.queue : k \in r.held /\ r.ans[k] = "none" /\ r.callLeft[k] > 0}
           proc == r.queue \ wait
           ok == {k \in proc : r.callLeft[k] > 0
                               /\ (r.apprLeft > 0 \/ k \in r.held)
                               /\ r.ans[k] = "ok"
                               /\ Need(k) \in r.scope}
       IN /\ proc /= {}
          /\ ss' = [ss EXCEPT !.n = @ + Cardinality(proc), !.queue = wait,
                    !.held = @ \cap wait, !.drained = @ \cup ok,
                    !.callLeft = [k \in Keys |-> IF k \in wait THEN r.callLeft[k] ELSE NoTimer],
                    !.ans = [k \in Keys |-> IF k \in wait THEN r.ans[k] ELSE "none"]]
    /\ last' = last

\* I12: a drained call is forwarded only after its DRAINED event, once per
\* bridge instance, never after its delivery was acknowledged.
\* @type: Str => Bool;
Forward(k) ==
    /\ Active /\ k \in ss.drained /\ k \notin ss.dlv /\ k \notin ss.sent
    /\ ss.hum = "None"
    /\ \/ ss.att = "Att"
       \/ k \in ss.opd
    /\ ss' = [ss EXCEPT !.fwd = @ \cup {k}, !.sent = @ \cup {k}]
    /\ last' = last

\* TOOL_CALL_DELIVERED: the runtime acknowledges a forwarded call.
\* @type: Str => Bool;
Deliver(k) ==
    /\ Active /\ k \in ss.fwd /\ k \in ss.drained /\ k \notin ss.dlv
    /\ ss' = [ss EXCEPT !.n = @ + 1, !.dlv = @ \cup {k}]
    /\ last' = last

\* I3, I10: narrowing is allowed in every cell; the version advances.
\* @type: Set(Str) => Bool;
Narrow(ns) ==
    /\ Active /\ ns \subseteq ss.scope /\ ns /= ss.scope /\ ss.ver < MaxVer
    /\ ss' = [ss EXCEPT !.n = @ + 1, !.scope = ns, !.ver = @ + 1]
    /\ last' = last

\* I3: a widening proposal, in any cell, is rejected and changes nothing.
\* @type: Set(Str) => Bool;
Extend(ns) ==
    /\ Active /\ ~(ns \subseteq ss.scope)
    /\ ss' = [ss EXCEPT !.n = @ + 1]
    /\ last' = last

Challenge ==
    /\ Active /\ ss.nid < MaxNonce
    /\ Cardinality(LiveSet(ss)) < LiveLimit
    /\ ss' = [ss EXCEPT !.nid = @ + 1, !.nb[ss.nid + 1] = TNonce]
    /\ last' = last

\* src is "honest" or "adv"; sg is the signature the request carries.
\* @type: (Str, Bool, Str, $sig, Int, Str) => Bool;
Present(src, keep, key, sg, claimed, pre) ==
    /\ Active
    /\ LET r == ss
           known == key \in r.K /\ Verifies(key, sg, claimed, pre)
           authentic == known /\ key \notin r.rev
           issued == claimed >= 1 /\ claimed <= r.nid
           live == issued /\ r.nb[claimed] > 0 /\ claimed \notin r.nu
           accept == authentic /\ live /\ pre = "ok" /\ r.att /= "Res"
           spent == r.nu \cup (IF known /\ issued THEN {claimed} ELSE {})
           recorded == known \/ r.uf < FailMax
           ufn == IF known THEN 0 ELSE r.uf + 1
           o == IF src = "honest" /\ keep /\ AttackOn /\ Cardinality(r.obs) < ObsMax
                THEN r.obs \cup {[by |-> key, nonce |-> claimed, pre |-> pre]}
                ELSE r.obs
       IN /\ last' = [auth |-> authentic, live |-> live, pre |-> pre,
                      known |-> known, rec |-> recorded, src |-> src]
          /\ IF ~recorded
             THEN ss' = [ss EXCEPT !.obs = o]
             ELSE IF accept /\ r.att = "Att"
             THEN ss' = [ss EXCEPT !.n = @ + 1, !.C = @ \cup {key},
                         !.nu = @ \cup {claimed}, !.uf = ufn, !.obs = o]
             ELSE IF accept /\ r.att = "Det"
             THEN ss' = [ss EXCEPT !.n = @ + 1, !.att = "Res", !.rk = key,
                         !.recorded = FALSE, !.detLeft = NoTimer,
                         !.nu = @ \cup {claimed}, !.uf = ufn, !.obs = o]
             ELSE ss' = [ss EXCEPT !.n = @ + 1, !.nu = spent, !.uf = ufn, !.obs = o]

\* @type: (Str, Str) => Bool;
AddClient(c, d) ==
    /\ Active /\ ss.att = "Att" /\ c \in ss.C \ ss.rev /\ d \notin ss.K
    /\ d \in Clients
    /\ ss' = [ss EXCEPT !.n = @ + 1, !.K = @ \cup {d}]
    /\ last' = last

\* @type: (Str, Str) => Bool;
Revoke(c, why) ==
    /\ Active /\ c \in ss.K \ ss.rev
    /\ LET r == ss
           rv == r.rev \cup {c}
           hd == IF why = "compromise" THEN r.hard \cup {c} ELSE r.hard
       IN IF why = "rotation"
          THEN ss' = [ss EXCEPT !.n = @ + 1, !.rev = rv, !.hard = hd]
          ELSE IF r.att = "Att" /\ r.C = {c}
          THEN ss' = [ss EXCEPT !.n = @ + 3, !.rev = rv, !.hard = hd, !.C = {},
                      !.att = "Det", !.detLeft = TDetach, !.recorded = TRUE]
          ELSE IF r.att = "Att" /\ c \in r.C
          THEN ss' = [ss EXCEPT !.n = @ + 2, !.rev = rv, !.hard = hd, !.C = @ \ {c}]
          ELSE IF r.att = "Res" /\ r.rk = c
          THEN ss' = [ss EXCEPT !.n = @ + 3, !.rev = rv, !.hard = hd, !.att = "Det",
                      !.rk = "none", !.detLeft = TDetach, !.recorded = TRUE]
          ELSE ss' = [ss EXCEPT !.n = @ + 1, !.rev = rv, !.hard = hd]
    /\ last' = last

\* The only recovery from key_exhausted: a new key; revoked keys stay revoked.
\* @type: Str => Bool;
OperatorAddKey(d) ==
    /\ ss.life = "Active" /\ ~ss.quar /\ ExhR(ss)
    /\ d \in Clients \ ss.K
    /\ ss' = [ss EXCEPT !.n = @ + 1, !.K = @ \cup {d}]
    /\ last' = last

\* An operator ends a quarantined or key-exhausted session (the only way out
\* of rule Q, and the alternative to OperatorAddKey).
OperatorEnd ==
    /\ ss.life = "Active" /\ (ss.quar \/ ExhR(ss))
    /\ ss' = [ss EXCEPT !.n = @ + 1, !.life = "Terminated", !.endWhy = "operator"]
    /\ last' = last

CompleteResume ==
    /\ Active /\ ss.att = "Res"
    /\ IF ss.corrupt
       THEN ss' = [ss EXCEPT !.n = @ + 1, !.quar = TRUE]     \* RESUME_FAILED: rule Q
       ELSE ss' = [ss EXCEPT !.n = @ + 1, !.att = "Att", !.C = {ss.rk}, !.rk = "none"]
    /\ last' = last

\* Environment: tampering with the stored log (detected by I5 at the next
\* verification).
Corrupt ==
    /\ AllowFaults /\ Active /\ ~ss.corrupt
    /\ ss' = [ss EXCEPT !.corrupt = TRUE]
    /\ last' = last

Timeout ==
    /\ Live
    /\ LET d == ss.att = "Det" /\ (ss.detLeft = 0 \/ ss.totLeft = 0)
           h == ss.hum = "Pend" /\ ss.humLeft = 0
       IN /\ d \/ h
          /\ ss' = [ss EXCEPT !.n = @ + 1 + (IF d THEN 1 ELSE 0) + (IF h THEN 1 ELSE 0),
                    !.life = "Terminated", !.endWhy = "timeout"]
    /\ last' = last

Terminate ==
    /\ Active
    /\ ss' = [ss EXCEPT !.n = @ + 1, !.life = "Terminated", !.endWhy = "clean"]
    /\ last' = last

Tick ==
    /\ IF ss.life = "Terminated" \/ ss.quar THEN ss' = ss
       ELSE ss' = [ss EXCEPT
              !.detLeft = IF @ > 0 THEN @ - 1 ELSE @,
              !.totLeft = IF ss.att = "Det" /\ @ > 0 THEN @ - 1 ELSE @,
              !.humLeft = IF @ > 0 THEN @ - 1 ELSE @,
              !.apprLeft = IF @ > 0 THEN @ - 1 ELSE @,
              !.callLeft = [k \in Keys |->
                  IF k \in ss.queue /\ ss.callLeft[k] > 0
                  THEN ss.callLeft[k] - 1 ELSE ss.callLeft[k]],
              !.nb =[i \in 1..MaxNonce |-> IF ss.nb[i] > 0 THEN ss.nb[i] - 1 ELSE ss.nb[i]]]
    /\ last' = last

\* fault: a recovery fault (e.g. the key registry is unavailable); only with AllowFaults.
\* @type: Bool => Bool;
Restart(fault) ==
    /\ (~AllowFaults => ~fault)
    /\ IF ss.life = "Terminated" \/ ss.quar THEN ss' = ss
       ELSE IF fault \/ ss.corrupt
       THEN ss' = [ss EXCEPT !.quar = TRUE, !.n = @ + 1]       \* RECOVERY_FAILED: rule Q
       ELSE ss' = [ss EXCEPT !.att = "Det", !.detLeft = TDetach, !.C = {},
                   !.rk = "none", !.uf = 0, !.recorded = TRUE, !.n = @ + 3,
                   !.opd = {}, !.sent = {},
                   !.nb = [i \in 1..MaxNonce |-> NoTimer]]
    /\ last' = last

Core ==
    \/ Tick \/ Corrupt \/ Challenge \/ CompleteResume \/ Timeout \/ Terminate
    \/ Escalate \/ Resolve \/ OperatorEnd \/ Drain
    \/ \E k \in Keys : Submit(k) \/ ExpireCall(k) \/ Forward(k) \/ SubmitAway(k)
                       \/ Deliver(k)
    \/ \E k \in Keys, a \in {"ok", "bad", "deny"} : Answer(k, a)
    \/ \E ns \in SUBSET Perms : Narrow(ns) \/ Extend(ns)
    \/ \E fault \in BOOLEAN : Restart(fault)
    \/ \E c \in Clients : Disconnect(c)
    \/ \E c, d \in Clients : AddClient(c, d)
    \/ \E d \in Clients : OperatorAddKey(d)
    \/ \E c \in Clients, w \in {"rotation", "compromise"} : Revoke(c, w)
    \/ \E key \in Clients, claimed \in 1..MaxNonce, pre \in {"ok", "bad"},
          keep \in BOOLEAN :
          claimed <= ss.nid /\
          Present("honest", keep, key, [by |-> key, nonce |-> claimed, pre |-> pre],
                  claimed, pre)
    \* the attacker signs with a key it holds (AdvSigs of the TLC model) ...
    \/ \E key \in Clients \cup AdvKeys, claimed \in 0..MaxNonce, pre \in {"ok", "bad"},
          by \in AdvKeys :
          AttackOn /\
          Present("adv", FALSE, key, [by |-> by, nonce |-> claimed, pre |-> pre], claimed, pre)
    \* ... or replays a signature it observed
    \/ \E key \in Clients \cup AdvKeys, claimed \in 0..MaxNonce, pre \in {"ok", "bad"},
          sg \in ss.obs :
          AttackOn /\ Present("adv", FALSE, key, sg, claimed, pre)

Next == Core /\ prv' = ss

(***************************************************************************)
(* State invariants                                                        *)
(***************************************************************************)
TypeOK ==
    /\ ss.att \in {"Att", "Det", "Res"} /\ ss.hum \in {"None", "Pend"}
    /\ ss.life \in {"Active", "Terminated"}
    /\ ss.n >= 1
    /\ ss.K \subseteq Clients /\ ss.C \subseteq Clients
    /\ ss.rev \subseteq ss.K /\ ss.hard \subseteq ss.rev
    /\ ss.rk \in Clients \cup {"none"}
    /\ ss.nid >= 0 /\ ss.nid <= MaxNonce /\ (\A i \in ss.nu : i >= 1 /\ i <= ss.nid)
    /\ DOMAIN ss.nb = 1..MaxNonce
    /\ \A i \in 1..MaxNonce : ss.nb[i] >= NoTimer /\ ss.nb[i] <= TNonce
    /\ ss.uf >= 0 /\ ss.uf <= FailMax
    /\ \A o \in ss.obs : o.by \in Clients /\ o.nonce \in 1..MaxNonce /\ o.pre \in {"ok", "bad"}
    /\ Cardinality(ss.obs) <= ObsMax /\ (~AttackOn => ss.obs = {})
    /\ ss.detLeft >= NoTimer /\ ss.detLeft <= TDetach
    /\ ss.humLeft >= NoTimer /\ ss.humLeft <= THuman
    /\ ss.totLeft >= 0 /\ ss.totLeft <= TTotal
    /\ ss.endWhy \in {"none", "timeout", "clean", "operator"}
    /\ ss.scope \subseteq Perms /\ ss.ver >= 0 /\ ss.ver <= MaxVer
    /\ ss.queue \subseteq Keys /\ ss.used \subseteq Keys /\ ss.drained \subseteq Keys
    /\ ss.fwd \subseteq Keys
    /\ DOMAIN ss.callLeft = Keys /\ DOMAIN ss.ans = Keys
    /\ \A k \in Keys : ss.callLeft[k] >= NoTimer /\ ss.callLeft[k] <= TCall
                       /\ ss.ans[k] \in {"none", "ok", "bad", "deny"}
    /\ ss.apprLeft >= 0 /\ ss.apprLeft <= TApprove
    /\ ss.held \subseteq ss.queue /\ ss.opd \subseteq ss.drained
    /\ ss.dlv \subseteq ss.drained /\ ss.sent \subseteq ss.drained
    /\ ss.quar \in BOOLEAN /\ ss.corrupt \in BOOLEAN

\* I2, I12: nothing is forwarded unless its DRAINED event is committed
I2 == ss.fwd \subseteq ss.drained
\* forwarding acknowledgement: only a forwarded call is delivered
Ack == ss.dlv \subseteq ss.fwd
I3 == ss.scope \subseteq Perms
I10 == (ss.ver = 0) <=> (ss.scope = Perms)
I13 == Cardinality(ss.queue) <= QMax
       /\ ss.queue \subseteq ss.used /\ ss.drained \subseteq ss.used
       /\ ss.queue \cap ss.drained = {}

I1 == (Live /\ ss.att = "Det") => ss.recorded
EndCause == ss.life = "Terminated" => ss.endWhy /= "none"
I9 == \A i \in 1..MaxNonce : ss.nb[i] >= NoTimer /\ ss.nb[i] <= TNonce
IBook == Cardinality(LiveSet(ss)) <= LiveLimit
IFail == ss.uf <= FailMax
I15 == Live =>
    /\ ss.C \subseteq ss.K
    /\ (ss.att = "Att") <=> (ss.C /= {})
    /\ (ss.att = "Res") <=> (ss.rk /= "none")
    /\ ss.rk /= "none" => ss.rk \in ss.K
I6 == ss.life = "Terminated" => ss.n >= 1
IRev == ss.C \cap ss.hard = {} /\ ss.rk \notin ss.hard
Timers == Live =>
    /\ (ss.att = "Det") <=> (ss.detLeft /= NoTimer)
    /\ (ss.hum = "Pend") <=> (ss.humLeft /= NoTimer)
\* The unforgeability consequence: only keys of Clients are ever registered.
KeysHonest == ss.K \subseteq Clients /\ ss.K \cap AdvKeys = {}

\* I11g, state form: a request whose signature verified left the failure count at 0
LastInv == last.known => (last.rec /\ ss.uf = 0)

StateInv == TypeOK /\ LastInv /\ I1 /\ I2 /\ Ack /\ I3 /\ I10 /\ I13 /\ EndCause /\ I9 /\ IBook /\ IFail /\ I15 /\ I6
            /\ IRev /\ Timers /\ KeysHonest

(***************************************************************************)
(* Step properties of BridgeContract.tla (StepProps), over (prv, ss, last).*)
(* Checked as invariants of the inductive step: prv is the previous record.*)
(***************************************************************************)
\* @type: $rec => <<Str, Str, Str, Set(Str), Set(Str), Str, Set(Str), Set(Str), Set(Str), Int, Set(Str), Set(Str), Str -> Str, Bool>>;
CellOf(r) == <<r.att, r.hum, r.life, r.K, r.C, r.rk, r.rev, r.hard,
               r.scope, r.ver, r.queue, r.drained, r.ans, r.quar>>

\* I6: nothing about a terminated session ever changes again
SP_I6 == prv.life = "Terminated" => ss = prv
\* I7: the cell changes only together with new committed events
SP_I7 == CellOf(ss) /= CellOf(prv) => ss.n > prv.n
\* I4, I9, I11, I15, NoForgery: entering Res, or adding a connected client
SP_Enter ==
    ((prv.att /= "Res" /\ ss.att = "Res")
     \/ (prv.att = "Att" /\ ss.att = "Att" /\ (ss.C \ prv.C) /= {})) =>
      /\ last.auth /\ last.live /\ last.pre = "ok"
      /\ \E i \in ss.nu \ prv.nu :
           /\ i >= 1 /\ i <= prv.nid /\ prv.nb[i] > 0
           /\ (last.src = "honest"
               \/ [by |-> IF ss.att = "Res" /\ prv.att /= "Res" THEN ss.rk
                          ELSE (CHOOSE c \in ss.C \ prv.C : TRUE),
                   nonce |-> i, pre |-> "ok"] \in ss.obs)
\* I11d: a nonce once spent stays spent
SP_Spent == prv.nu \subseteq ss.nu
\* I11f: issuing a challenge never invalidates a live nonce
SP_Issue == ss.nid /= prv.nid => LiveSet(prv) \subseteq LiveSet(ss)
\* T_total: never reset, runs down only while detached
SP_Total == ss.totLeft <= prv.totLeft /\ (ss.totLeft < prv.totLeft => prv.att = "Det")
\* I15d
SP_Register == ss.K /= prv.K =>
    \/ ExhR(prv)
    \/ (prv.att = "Att" /\ (prv.C \ prv.rev) /= {})
\* I11-REVOKE: monotone; a joining client is not revoked
SP_Revoke == prv.K \subseteq ss.K /\ prv.rev \subseteq ss.rev /\ prv.hard \subseteq ss.hard
SP_Join == (prv.att = "Att" /\ ss.att = "Att") => ((ss.C \ prv.C) \cap prv.rev = {})
\* key_exhausted: no client operation is served
SP_Exhausted ==
    ExhR(prv) =>
      \/ ss = prv
      \/ ss.endWhy \in {"operator", "timeout"}
      \/ ((ss.K \ prv.K) /= {} /\ ss.rev = prv.rev /\ ss.att = prv.att /\ ss.life = "Active")
      \/ (ss.life = "Active" /\ ss.K = prv.K /\ ss.rev = prv.rev /\ ss.hum = prv.hum
          /\ ss.scope = prv.scope /\ ss.queue = prv.queue
          /\ ss.drained = prv.drained /\ ss.ans = prv.ans
          /\ (ss.att /= prv.att => ss.att = "Det"))
\* I15b
SP_Shrink == (prv.att = "Att" /\ ss.C \subseteq prv.C /\ ss.C /= prv.C /\ ss.C /= {}) =>
    ss.att = "Att"
\* leaving Det
SP_LeaveDet == (prv.att = "Det" /\ ss.att /= "Det") =>
    (ss.att = "Res" \/ ss.life = "Terminated")

\* I3: scope only narrows, in every cell
SP_Scope == ss.scope \subseteq prv.scope
\* I10: version +1 exactly when the scope strictly narrows
SP_Version == ((ss.ver = prv.ver + 1) <=> (ss.scope /= prv.scope))
              /\ (ss.ver = prv.ver \/ ss.ver = prv.ver + 1)
\* Rule D, I13: calls drain only in (Att, None) (the operator's allowlist
\* excepted), only calls in time, approved (a held call by its own answer) and
\* permitted by the current scope
SP_Drain == \A k \in ss.drained \ prv.drained :
    /\ prv.hum = "None" /\ Need(k) \in prv.scope
    /\ \/ k \in ss.opd
       \/ /\ prv.att = "Att"
          /\ prv.callLeft[k] > 0
          /\ (prv.apprLeft > 0 \/ k \in prv.held)
          /\ prv.ans[k] = "ok"
\* I2, I12: forwarding only while h = None, in Att or (operator-drained) away,
\* after commit, never after acknowledgement
SP_Forward == \A k \in ss.sent \ prv.sent :
    /\ prv.hum = "None" /\ k \notin prv.dlv
    /\ (prv.att = "Att" \/ k \in prv.opd)
\* the operator's allowlist is the only way to drain away
SP_Allow == \A k \in ss.opd \ prv.opd : Need(k) \in Allow

\* I5: verification succeeds only on an intact chain
SP_Chain == (prv.att /= "Att" /\ ss.att = "Att") => ~prv.corrupt
\* rule Q: a quarantined session changes only by an operator's end
SP_Quarantine == prv.quar => (ss = prv \/ ss.endWhy = "operator")

StepInv == SP_Chain /\ SP_Quarantine /\ SP_Scope /\ SP_Version /\ SP_Drain /\ SP_Forward /\ SP_Allow
           /\ SP_I6 /\ SP_I7 /\ SP_Enter /\ SP_Spent /\ SP_Issue
           /\ SP_Total /\ SP_Register /\ SP_Revoke /\ SP_Join /\ SP_Exhausted
           /\ SP_Shrink /\ SP_LeaveDet

Inv == StateInv /\ StepInv

\* Inductive step.  The state invariants are assumed at the start, with prv = ss
\* (a stuttering start, so StepInv holds trivially there); StepInv is checked at
\* the state after the step, where prv is the record before it.
IndInit ==
    /\ ss = Gen(4) /\ prv = ss
    /\ last \in [auth: BOOLEAN, live: BOOLEAN, pre: {"ok", "bad", "none"},
                 known: BOOLEAN, rec: BOOLEAN, src: {"honest", "adv"}]
    /\ StateInv

\* Non-vacuity: must FAIL at length 0 (a resuming session exists).
Witness == ~(ss.att = "Res" /\ ss.life = "Active" /\ ss.hum = "Pend")

\* Non-vacuity of the attacker: must FAIL at length 1 from IndInit (a step in
\* which the attacker replays an observed signature that authenticates, and the
\* request is accepted: a nonce is spent and a client joins or a resume starts).
WitnessFail == ~(last.src = "adv" /\ ~last.known /\ ss.uf > prv.uf)
WitnessAdv ==~(last.src = "adv" /\ last.auth /\ ss.nu /= prv.nu
                /\ (ss.att /= prv.att \/ ss.C /= prv.C))
=============================================================================
