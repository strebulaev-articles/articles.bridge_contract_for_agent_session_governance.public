------------------------------ MODULE BridgeFull ------------------------------
(***************************************************************************)
(* Typed single-session version of BridgeContract.tla for Apalache         *)
(* (inductive checking), grown from BridgeSlice.tla one feature group at a *)
(* time.  The invariants of BridgeContract.tla are all per session, and    *)
(* sessions interact only through the global Tick, so one session carries  *)
(* them; multi-session behaviour is not claimed.  Dropped on purpose: the  *)
(* model bounds MaxEvents and MaxRestarts (the event count n is unbounded  *)
(* here), the switch GhostOn (the ghost is always written), the two        *)
(* conjuncts that use ENABLED (Apalache has no ENABLED: a challenge is     *)
(* answered the same way for every key id, in I11; a timer that ran out    *)
(* makes the timeout due, in Timers) and the hash chain (not modelled      *)
(* anywhere).  A record is updated by EXCEPT because Apalache does not     *)
(* type the record merge (@@).                                             *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, Apalache

\* @typeAlias: sig = { by: Str, nonce: Int, pre: Str };
\* @typeAlias: rec = { att: Str, hum: Str, life: Str, n: Int, K: Set(Str),
\*   C: Set(Str), rk: Str, rev: Set(Str), hard: Set(Str), recorded: Bool,
\*   nid: Int, nb: Int -> Int, nk: Int -> Str, ng: Int -> Bool, nu: Set(Int),
\*   nr: Int -> Set(Str), uf: Int, obs: Set($sig),
\*   detLeft: Int, humLeft: Int, totLeft: Int, endWhy: Str,
\*   scope: Set(Str), ver: Int, queue: Set(Str), callLeft: Str -> Int,
\*   used: Set(Str), ans: Str -> Str, appr: Str -> Int, drained: Set(Str),
\*   held: Set(Str), opd: Set(Str), dlv: Set(Str), sent: Set(Str),
\*   fwd: Set(Str), quar: Bool, corrupt: Bool };
\* @typeAlias: lst = { auth: Bool, live: Bool, pre: Str, known: Bool,
\*   rec: Bool, src: Str, call: Str, fw: Bool };
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

\* The key ids a challenge can name: the client keys and the attacker's own.
KeyIds == Clients \cup (IF AttackOn THEN AdvKeys ELSE {})

VARIABLES
    \* @type: $rec;
    ss,
    \* @type: $rec;
    prv,         \* ghost: the record before the last step (for step properties)
    \* @type: $lst;
    last,        \* ghost: the last request answered (a presentation or a direct call)
    \* @type: $lst;
    pl           \* ghost: `last` before the last step

vars == <<ss, prv, last, pl>>

NoTimer == -1

InitRec == [ att |-> "Att", hum |-> "None", life |-> "Active", n |-> 1,
             K |-> {"c1"}, C |-> {"c1"}, rk |-> "none",
             rev |-> {}, hard |-> {}, recorded |-> FALSE,
             nid |-> 0, nb |-> [i \in 1..MaxNonce |-> NoTimer],
             nk |-> [i \in 1..MaxNonce |-> "none"],
             ng |-> [i \in 1..MaxNonce |-> FALSE], nu |-> {},
             nr |-> [i \in 1..MaxNonce |-> {}],
             uf |-> 0, obs |-> {}, detLeft |-> NoTimer, humLeft |-> NoTimer,
             totLeft |-> TTotal, endWhy |-> "none",
             scope |-> Perms, ver |-> 0, queue |-> {},
             callLeft |-> [k \in Keys |-> NoTimer], used |-> {},
             ans |-> [k \in Keys |-> "none"],
             appr |-> [k \in Keys |-> NoTimer], drained |-> {},
             held |-> {}, opd |-> {}, dlv |-> {}, sent |-> {}, fwd |-> {},
             quar |-> FALSE, corrupt |-> FALSE ]

InitLast == [auth |-> FALSE, live |-> FALSE, pre |-> "none", known |-> FALSE,
             rec |-> TRUE, src |-> "honest", call |-> "none", fw |-> FALSE]

Init == ss = InitRec /\ prv = InitRec /\ last = InitLast /\ pl = InitLast

\* @type: $rec => Bool;
ExhR(r) == r.K /= {} /\ r.K \subseteq r.rev

Live == ss.life = "Active" /\ ~ss.quar
Active == Live /\ ~ExhR(ss)
\* @type: $rec => Set(Int);
LiveSet(r) == {i \in 1..MaxNonce : i <= r.nid /\ r.nb[i] > 0 /\ i \notin r.nu}

\* @type: (Str, $sig, Int, Str) => Bool;
Verifies(key, sg, claimed, pre) ==
    sg.by = key /\ sg.nonce = claimed /\ sg.pre = pre

\* TERMINATION and its effects: k events, the queue discarded, no timer left,
\* the nonces void.
\* @type: ($rec, Int, Str) => $rec;
Ended(r, k, why) ==
    [r EXCEPT !.n = @ + k, !.life = "Terminated", !.endWhy = why,
              !.queue = {}, !.held = {},
              !.callLeft = [x \in Keys |-> NoTimer],
              !.appr = [x \in Keys |-> NoTimer],
              !.ans = [x \in Keys |-> "none"],
              !.detLeft = NoTimer, !.humLeft = NoTimer,
              !.nb = [i \in 1..MaxNonce |-> NoTimer]]

(***************************************************************************)
(* Actions (each leaves last unchanged unless it answers a request)        *)
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

\* HUMAN_RESOLVED: the approval of every call queued during this escalation
\* starts here, one countdown per call; a call that has one keeps it.
Resolve ==
    /\ Active /\ ss.hum = "Pend" /\ ss.humLeft > 0
    /\ ss' = [ss EXCEPT !.n = @ + 1, !.hum = "None", !.humLeft = NoTimer,
              !.appr = [k \in Keys |->
                          IF k \in ss.queue \ ss.held /\ ss.appr[k] = NoTimer
                          THEN TApprove ELSE ss.appr[k]]]
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
              !.callLeft[k] = NoTimer, !.appr[k] = NoTimer, !.ans[k] = "none"]
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

\* A call arrives in (Att, None) with no escalation pending.  Inside the
\* scope it goes straight to the runtime and leaves no event; outside the
\* scope it is refused and recorded (TOOL_CALL_REJECTED, reason scope).
\* @type: Str => Bool;
Direct(k) ==
    /\ Active /\ ss.att = "Att" /\ ss.hum = "None" /\ k \notin ss.used
    /\ LET inscope == Need(k) \in ss.scope IN
         /\ IF inscope THEN ss' = ss ELSE ss' = [ss EXCEPT !.n = @ + 1]
         /\ last' = [auth |-> FALSE, live |-> FALSE, pre |-> "none",
                     known |-> FALSE, rec |-> TRUE, src |-> "honest",
                     call |-> k, fw |-> inscope]

\* Rule D + I13 + I14: drain in (Att, None), revalidating each call.
Drain ==
    /\ Active /\ ss.att = "Att" /\ ss.hum = "None" /\ ss.queue /= {}
    /\ LET r == ss
           wait == {k \in r.queue : k \in r.held /\ r.ans[k] = "none" /\ r.callLeft[k] > 0}
           proc == r.queue \ wait
           ok == {k \in proc : r.callLeft[k] > 0
                               /\ (r.appr[k] > 0 \/ k \in r.held)
                               /\ r.ans[k] = "ok"
                               /\ Need(k) \in r.scope}
       IN /\ proc /= {}
          /\ ss' = [ss EXCEPT !.n = @ + Cardinality(proc), !.queue = wait,
                    !.held = @ \cap wait, !.drained = @ \cup ok,
                    !.callLeft = [k \in Keys |-> IF k \in wait THEN r.callLeft[k] ELSE NoTimer],
                    !.appr = [k \in Keys |-> IF k \in wait THEN r.appr[k] ELSE NoTimer],
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

\* A challenge under the key id kid: a fresh nonce bound to kid.  The guard
\* does not read kid; what differs is the bridge's note of whether kid was a
\* registered, unrevoked key at this moment (ng).
\* @type: Str => Bool;
Challenge(kid) ==
    /\ Live /\ ss.nid < MaxNonce
    /\ Cardinality(LiveSet(ss)) < LiveLimit
    /\ ss' = [ss EXCEPT !.nid = @ + 1, !.nb[ss.nid + 1] = TNonce,
              !.nk[ss.nid + 1] = kid,
              !.ng[ss.nid + 1] = (kid \in ss.K \ ss.rev)]
    /\ last' = last

\* src is "honest" or "adv"; sg is the signature the request carries.
\* @type: (Str, Bool, Str, $sig, Int, Str) => Bool;
Present(src, keep, key, sg, claimed, pre) ==
    /\ Live
    /\ LET r == ss
           issued == claimed >= 1 /\ claimed <= r.nid
           bound == issued /\ r.nk[claimed] = key /\ r.ng[claimed]
           known == key \in r.K /\ Verifies(key, sg, claimed, pre) /\ bound
           authentic == known /\ key \notin r.rev
           live == issued /\ r.nb[claimed] > 0 /\ claimed \notin r.nu
           accept == authentic /\ live /\ pre = "ok" /\ r.att /= "Res"
           spent == r.nu \cup (IF known THEN {claimed} ELSE {})
           recorded == known \/ r.uf < FailMax
           ufn == IF known THEN 0 ELSE r.uf + 1
           o == IF src = "honest" /\ keep /\ AttackOn /\ Cardinality(r.obs) < ObsMax
                THEN r.obs \cup {[by |-> key, nonce |-> claimed, pre |-> pre]}
                ELSE r.obs
           wf == issued /\ pre = "ok" /\ key \in Clients
                 /\ Verifies(key, sg, claimed, pre)
           nrn == IF wf /\ ~accept
                  THEN [r.nr EXCEPT ![claimed] = @ \cup {key}] ELSE r.nr
       IN /\ last' = [auth |-> authentic, live |-> live, pre |-> pre,
                      known |-> known, rec |-> recorded, src |-> src,
                      call |-> "none", fw |-> FALSE]
          /\ IF ~recorded
             THEN ss' = [ss EXCEPT !.obs = o, !.nr = nrn]
             ELSE IF accept /\ r.att = "Att"
             THEN ss' = [ss EXCEPT !.n = @ + 1, !.C = @ \cup {key},
                         !.nu = @ \cup {claimed}, !.uf = ufn, !.obs = o]
             ELSE IF accept /\ r.att = "Det"
             THEN ss' = [ss EXCEPT !.n = @ + 1, !.att = "Res", !.rk = key,
                         !.recorded = FALSE, !.detLeft = NoTimer,
                         !.nu = @ \cup {claimed}, !.uf = ufn, !.obs = o]
             ELSE ss' = [ss EXCEPT !.n = @ + 1, !.nu = spent, !.uf = ufn, !.obs = o,
                         !.nr = nrn]

\* An honest client signs, with its own key, the nonce and verdict it sends.
\* @type: (Bool, Str, Int, Str) => Bool;
PresentHonest(keep, key, claimed, pre) ==
    /\ claimed <= ss.nid
    /\ Present("honest", keep, key, [by |-> key, nonce |-> claimed, pre |-> pre],
               claimed, pre)

\* The attacker signs with a key it holds (AdvSigs of the TLC model) or
\* replays a signature it observed.
\* @type: (Str, Int, Str) => Bool;
PresentAdv(key, claimed, pre) ==
    /\ AttackOn
    /\ \/ \E by \in AdvKeys :
            Present("adv", FALSE, key, [by |-> by, nonce |-> claimed, pre |-> pre],
                    claimed, pre)
       \/ \E sg \in ss.obs : Present("adv", FALSE, key, sg, claimed, pre)

\* @type: (Str, Str) => Bool;
AddClient(c, d) ==
    /\ Active /\ ss.att = "Att" /\ c \in ss.C \ ss.rev /\ d \notin ss.K
    /\ d \in Clients
    /\ ss' = [ss EXCEPT !.n = @ + 1, !.K = @ \cup {d}]
    /\ last' = last

\* KEY_REVOKED.  A re-attach the key is verifying is abandoned whatever the
\* reason; otherwise a compromise detaches a connected client and a rotation
\* only stops new re-attach and join.
\* @type: (Str, Str) => Bool;
Revoke(c, why) ==
    /\ Active /\ c \in ss.K \ ss.rev
    /\ LET r == ss
           rv == r.rev \cup {c}
           hd == IF why = "compromise" THEN r.hard \cup {c} ELSE r.hard
       IN IF r.att = "Res" /\ r.rk = c
          THEN ss' = [ss EXCEPT !.n = @ + 3, !.rev = rv, !.hard = hd, !.att = "Det",
                      !.rk = "none", !.detLeft = TDetach, !.recorded = TRUE]
          ELSE IF why = "rotation"
          THEN ss' = [ss EXCEPT !.n = @ + 1, !.rev = rv, !.hard = hd]
          ELSE IF r.att = "Att" /\ r.C = {c}
          THEN ss' = [ss EXCEPT !.n = @ + 3, !.rev = rv, !.hard = hd, !.C = {},
                      !.att = "Det", !.detLeft = TDetach, !.recorded = TRUE]
          ELSE IF r.att = "Att" /\ c \in r.C
          THEN ss' = [ss EXCEPT !.n = @ + 2, !.rev = rv, !.hard = hd, !.C = @ \ {c}]
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
    /\ ss' = Ended(ss, 1, "operator")
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
          /\ ss' = Ended(ss, 1 + (IF d THEN 1 ELSE 0) + (IF h THEN 1 ELSE 0), "timeout")
    /\ last' = last

Terminate ==
    /\ Active
    /\ ss' = Ended(ss, 1, "clean")
    /\ last' = last

Tick ==
    /\ IF ss.life = "Terminated" \/ ss.quar THEN ss' = ss
       ELSE ss' = [ss EXCEPT
              !.detLeft = IF @ > 0 THEN @ - 1 ELSE @,
              !.totLeft = IF ss.att = "Det" /\ @ > 0 THEN @ - 1 ELSE @,
              !.humLeft = IF @ > 0 THEN @ - 1 ELSE @,
              !.appr = [k \in Keys |-> IF ss.appr[k] > 0 THEN ss.appr[k] - 1 ELSE ss.appr[k]],
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
                   !.nb = [i \in 1..MaxNonce |-> NoTimer],
                   !.nk = [i \in 1..MaxNonce |-> "none"],
                   !.ng = [i \in 1..MaxNonce |-> FALSE],
                   !.nr = [i \in 1..MaxNonce |-> {}]]
    /\ last' = last

Core ==
    \/ Tick \/ Corrupt \/ CompleteResume \/ Timeout \/ Terminate
    \/ Escalate \/ Resolve \/ OperatorEnd \/ Drain
    \/ \E kid \in KeyIds : Challenge(kid)
    \/ \E k \in Keys : Submit(k) \/ ExpireCall(k) \/ Forward(k) \/ SubmitAway(k)
                       \/ Deliver(k) \/ Direct(k)
    \/ \E k \in Keys, a \in {"ok", "bad", "deny"} : Answer(k, a)
    \/ \E ns \in SUBSET Perms : Narrow(ns) \/ Extend(ns)
    \/ \E fault \in BOOLEAN : Restart(fault)
    \/ \E c \in Clients : Disconnect(c)
    \/ \E c, d \in Clients : AddClient(c, d)
    \/ \E d \in Clients : OperatorAddKey(d)
    \/ \E c \in Clients, w \in {"rotation", "compromise"} : Revoke(c, w)
    \/ \E key \in Clients, claimed \in 1..MaxNonce, pre \in {"ok", "bad"},
          keep \in BOOLEAN :
          PresentHonest(keep, key, claimed, pre)
    \/ \E key \in Clients \cup AdvKeys, claimed \in 0..MaxNonce, pre \in {"ok", "bad"} :
          PresentAdv(key, claimed, pre)

Next == Core /\ prv' = ss /\ pl' = last

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
    /\ DOMAIN ss.nb = 1..MaxNonce /\ DOMAIN ss.nk = 1..MaxNonce
    /\ DOMAIN ss.ng = 1..MaxNonce /\ DOMAIN ss.nr = 1..MaxNonce
    /\ \A i \in 1..MaxNonce : /\ ss.nb[i] >= NoTimer /\ ss.nb[i] <= TNonce
                              /\ ss.nk[i] \in KeyIds \cup {"none"}
                              /\ ss.nr[i] \subseteq Clients
    /\ ss.uf >= 0
    /\ \A o \in ss.obs : o.by \in Clients /\ o.nonce \in 1..MaxNonce /\ o.pre \in {"ok", "bad"}
    /\ Cardinality(ss.obs) <= ObsMax /\ (~AttackOn => ss.obs = {})
    /\ ss.detLeft >= NoTimer /\ ss.detLeft <= TDetach
    /\ ss.humLeft >= NoTimer /\ ss.humLeft <= THuman
    /\ ss.totLeft >= 0 /\ ss.totLeft <= TTotal
    /\ ss.endWhy \in {"none", "timeout", "clean", "operator"}
    /\ ss.scope \subseteq Perms /\ ss.ver >= 0 /\ ss.ver <= MaxVer
    /\ ss.queue \subseteq Keys /\ ss.used \subseteq Keys /\ ss.drained \subseteq Keys
    /\ ss.fwd \subseteq Keys
    /\ DOMAIN ss.callLeft = Keys /\ DOMAIN ss.ans = Keys /\ DOMAIN ss.appr = Keys
    /\ \A k \in Keys : ss.callLeft[k] >= NoTimer /\ ss.callLeft[k] <= TCall
                       /\ ss.ans[k] \in {"none", "ok", "bad", "deny"}
                       /\ ss.appr[k] >= NoTimer /\ ss.appr[k] <= TApprove
    /\ ss.held \subseteq ss.queue /\ ss.opd \subseteq ss.drained
    /\ ss.dlv \subseteq ss.drained /\ ss.sent \subseteq ss.drained
    /\ ss.quar \in BOOLEAN /\ ss.corrupt \in BOOLEAN

\* I2, I12: nothing is forwarded unless its DRAINED event is committed
I2 == ss.fwd \subseteq ss.drained
\* forwarding acknowledgement: only a forwarded call is delivered
Ack == ss.dlv \subseteq ss.fwd
I10 == (ss.ver = 0) <=> (ss.scope = Perms)
I13 == Cardinality(ss.queue) <= QMax
       /\ ss.queue \subseteq ss.used /\ ss.drained \subseteq ss.used
       /\ ss.queue \cap ss.drained = {}

I1 == (Live /\ ss.att = "Det") => ss.recorded
EndCause == ss.life = "Terminated" => ss.endWhy /= "none"
I9 == \A i \in 1..MaxNonce : ss.nb[i] >= NoTimer /\ ss.nb[i] <= TNonce
IBook == Cardinality(LiveSet(ss)) <= LiveLimit
IFail == ss.uf <= FailMax
\* I11, the nonce is bound to a key id at issue (the conjunct of the TLC model
\* that a challenge is answered the same way for every key id uses ENABLED and
\* is not here)
I11 == /\ \A i \in 1..MaxNonce :
            /\ (i <= ss.nid /\ ss.ng[i]) => ss.nk[i] \in ss.K
            /\ (i \in LiveSet(ss) /\ ss.ng[i]) =>
                 /\ ss.nk[i] \notin ss.nr[i]
                 /\ \A o \in ss.obs : ~(o.nonce = i /\ o.by = ss.nk[i])
            /\ i > ss.nid => ss.nr[i] = {}
       /\ \A o \in ss.obs : o.nonce <= ss.nid
I15 == Live =>
    /\ ss.C \subseteq ss.K
    /\ (ss.att = "Att") <=> (ss.C /= {})
    /\ (ss.att = "Res") <=> (ss.rk /= "none")
    /\ ss.rk /= "none" => ss.rk \in ss.K
\* I6: a terminated session has no queue obligation and no live timer
I6 == ss.life = "Terminated" =>
    /\ ss.queue = {}
    /\ ss.detLeft = NoTimer /\ ss.humLeft = NoTimer
    /\ \A k \in Keys : ss.callLeft[k] = NoTimer /\ ss.appr[k] = NoTimer
    /\ LiveSet(ss) = {}
\* I11-REVOKE: a key revoked for compromise is not connected, and a revoked
\* key is not being verified
IRev == ss.C \cap ss.hard = {} /\ ss.rk \notin ss.rev
\* Timers run exactly in the cells of Section 5.4 (the conjunct of the TLC
\* model that a timer that ran out makes the timeout due uses ENABLED and is
\* not here)
Timers == Live =>
    /\ (ss.att = "Det") <=> (ss.detLeft /= NoTimer)
    /\ (ss.hum = "Pend") <=> (ss.humLeft /= NoTimer)
    /\ \A k \in Keys :
         /\ (k \in ss.queue) <=> (ss.callLeft[k] /= NoTimer)
         /\ (ss.appr[k] /= NoTimer) => (k \in ss.queue \ ss.held)
         /\ (ss.hum = "None" /\ k \in ss.queue \ ss.held) => (ss.appr[k] /= NoTimer)
\* The unforgeability consequence: only keys of Clients are ever registered.
KeysHonest == ss.K \subseteq Clients /\ ss.K \cap AdvKeys = {}

\* I11g, state form: a request that authenticated left the failure count at 0
LastInv == last.known => (last.rec /\ ss.uf = 0)

StateInv == TypeOK /\ LastInv /\ I1 /\ I2 /\ Ack /\ I10 /\ I13 /\ EndCause /\ I9 /\ IBook /\ IFail /\ I11 /\ I15 /\ I6
            /\ IRev /\ Timers /\ KeysHonest

(***************************************************************************)
(* Step properties of BridgeContract.tla (StepProps), over (prv, ss, last).*)
(* Checked as invariants of the inductive step: prv is the previous record.*)
(***************************************************************************)
\* @type: $rec => <<Str, Str, Str, Set(Str), Set(Str), Str, Set(Str), Set(Str), Set(Str), Int, Set(Str), Set(Str), Str -> Str, Bool>>;
CellOf(r) == <<r.att, r.hum, r.life, r.K, r.C, r.rk, r.rev, r.hard,
               r.scope, r.ver, r.queue, r.drained, r.ans, r.quar>>

\* A re-attach starts (-> Res) or a client joins (the connected set grows).
Enters == \/ (prv.att /= "Res" /\ ss.att = "Res")
          \/ (prv.att = "Att" /\ ss.att = "Att" /\ (ss.C \ prv.C) /= {})
\* The key that does so.
Entered == IF prv.att /= "Res" /\ ss.att = "Res" THEN {ss.rk} ELSE ss.C \ prv.C

\* I6: nothing about a terminated session ever changes again
SP_I6 == prv.life = "Terminated" => ss = prv
\* I7: the cell changes only together with new committed events
SP_I7 == CellOf(ss) /= CellOf(prv) => ss.n > prv.n
\* I4, I9, I11, I15: entering Res, or adding a connected client, needs an
\* authentic request with a live, unused nonce and a prefix; the nonce is spent
\* by it and was issued for the key that enters, registered and unrevoked then
SP_Enter ==
    Enters =>
      /\ last.auth /\ last.live /\ last.pre = "ok"
      /\ \E i \in ss.nu \ prv.nu :
           /\ i >= 1 /\ i <= prv.nid /\ prv.nb[i] > 0
           /\ prv.ng[i] /\ Entered = {prv.nk[i]}
\* I11, honest presenter: every accepted re-attach or join was presented by an
\* honest client, never by the attacker
SP_Honest == Enters => last.src = "honest"
\* I11, no replay: a request that was presented and refused is never accepted
\* later
SP_NoReplay == Enters => \A i \in ss.nu \ prv.nu : Entered \cap prv.nr[i] = {}
\* I11d: a nonce once spent stays spent
SP_Spent == prv.nu \subseteq ss.nu
\* I11f: issuing a challenge never invalidates a live nonce, and the nonce
\* issued is live for T_nonce whatever key id it names
SP_Issue == ss.nid /= prv.nid =>
    /\ LiveSet(prv) \subseteq LiveSet(ss)
    /\ ss.nid = prv.nid + 1
    /\ ss.nb[ss.nid] = TNonce /\ ss.nid \notin ss.nu
\* T_total: never reset, runs down only while detached
SP_Total == ss.totLeft <= prv.totLeft /\ (ss.totLeft < prv.totLeft => prv.att = "Det")
\* a session ends by timeout only when a timer has run out
SP_Timeout ==
    /\ (ss.endWhy = "timeout" /\ prv.endWhy /= "timeout") =>
         \/ (prv.att = "Det" /\ (prv.detLeft = 0 \/ prv.totLeft = 0))
         \/ (prv.hum = "Pend" /\ prv.humLeft = 0)
    \* the timeout wins over a resolve in the tick of T_human
    /\ (prv.hum = "Pend" /\ ss.hum = "None") => prv.humLeft /= 0
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
          /\ ss.used = prv.used /\ ss.C \subseteq prv.C
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
          /\ (prv.appr[k] > 0 \/ k \in prv.held)
          /\ prv.ans[k] = "ok"
\* I13, approval: recorded once per call and only runs down
SP_Appr == \A k \in Keys :
    (prv.appr[k] /= NoTimer /\ ss.appr[k] /= NoTimer) => ss.appr[k] <= prv.appr[k]
\* I3, direct calls: straight to the runtime only in (Att, None) within the
\* scope; outside the scope refused, and the refusal is an event
SP_Direct == (last /= pl /\ last.call /= "none") =>
    /\ prv.att = "Att" /\ prv.hum = "None"
    /\ IF last.fw
       THEN Need(last.call) \in prv.scope /\ ss = prv
       ELSE Need(last.call) \notin prv.scope /\ ss.n > prv.n
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

StepInv == SP_Chain /\ SP_Quarantine /\ SP_Scope /\ SP_Version /\ SP_Drain /\ SP_Appr /\ SP_Direct
           /\ SP_Forward /\ SP_Allow
           /\ SP_I6 /\ SP_I7 /\ SP_Enter /\ SP_Honest /\ SP_NoReplay /\ SP_Spent /\ SP_Issue
           /\ SP_Total /\ SP_Timeout /\ SP_Register /\ SP_Revoke /\ SP_Join /\ SP_Exhausted
           /\ SP_Shrink /\ SP_LeaveDet

Inv == StateInv /\ StepInv

\* Inductive step.  The state invariants are assumed at the start, with prv = ss
\* and pl = last (a stuttering start, so StepInv holds trivially there);
\* StepInv is checked at the state after the step, where prv is the record
\* before it and pl the ghost before it.
IndInit ==
    /\ ss = Gen(4) /\ prv = ss
    /\ last \in [auth: BOOLEAN, live: BOOLEAN, pre: {"ok", "bad", "none"},
                 known: BOOLEAN, rec: BOOLEAN, src: {"honest", "adv"},
                 call: {"k1", "k2", "none"}, fw: BOOLEAN]
    /\ pl = last
    /\ StateInv

\* Non-vacuity: must FAIL at length 0 (a resuming session exists).
Witness == ~(ss.att = "Res" /\ ss.life = "Active" /\ ss.hum = "Pend")

\* Non-vacuity of the attacker: each must FAIL at length 1 from IndInit.
\* WitnessFail: the attacker presents a request that does not authenticate and
\* it is counted.  WitnessAdv: the attacker replays an observed signature that
\* authenticates (key, nonce and binding in order), and the request is refused
\* and recorded; that it is never accepted is SP_Honest.
WitnessFail == ~(last.src = "adv" /\ ~last.known /\ ss.uf > prv.uf)
WitnessAdv == ~(last /= pl /\ last.src = "adv" /\ last.known /\ ss.n > prv.n)
\* Non-vacuity of acceptance: must FAIL at length 1 (an honest request is
\* accepted: a client joins or a re-attach starts).
WitnessAccept == ~(last /= pl /\ last.src = "honest" /\ last.auth /\ last.live
                   /\ (ss.att /= prv.att \/ ss.C /= prv.C))
\* Non-vacuity of the direct path: must FAIL at length 1 (a call outside the
\* scope is refused).
WitnessDirect == ~(last /= pl /\ last.call /= "none" /\ ~last.fw)
=============================================================================
