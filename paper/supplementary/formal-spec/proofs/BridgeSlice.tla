------------------------------ MODULE BridgeSlice ------------------------------
(***************************************************************************)
(* Typed slice of BridgeContract.tla for Apalache (inductive checking).    *)
(*                                                                         *)
(* One session.  Kept: attachment cell, client set and key registry with   *)
(* revocation (I15, IRev), the nonce book (I9, I11 f), the failure record  *)
(* (I11 g), detach timers, and the attacker with its observed signatures.  *)
(* Dropped: human escalation, tool queue, drain, forward, scope, log       *)
(* corruption and quarantine.  A record is updated by EXCEPT because       *)
(* Apalache does not type the record merge (@@) of the TLC module.         *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, Apalache

\* @typeAlias: sig = { by: Str, nonce: Int, pre: Str };
\* @typeAlias: rec = { att: Str, life: Str, n: Int, K: Set(Str), C: Set(Str),
\*   rk: Str, rev: Set(Str), hard: Set(Str), recorded: Bool, nid: Int,
\*   nb: Int -> Int, nu: Set(Int), uf: Int, obs: Set($sig), detLeft: Int,
\*   totLeft: Int };
\* @typeAlias: adm = { src: Str, sg: $sig };
BS_aliases == TRUE

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
    TNonce,
    \* @type: Int;
    TTotal

MaxNonce == 3

CInit ==
    /\ Clients = {"c1", "c2", "c3"} /\ AdvKeys = {"x", "y"}
    /\ AttackOn = TRUE /\ ObsMax \in 0..3 /\ LiveLimit \in 1..3 /\ FailMax \in 1..3
    /\ TDetach \in 1..5 /\ TNonce \in 1..5 /\ TTotal \in 5..8

VARIABLES
    \* @type: $rec;
    ss,
    \* @type: Set($adm);
    adm          \* ghost: every admission (attach or join), who built it, its signature

vars == <<ss, adm>>

NoTimer == -1

InitRec == [ att |-> "Att", life |-> "Active", n |-> 1,
             K |-> {"c1"}, C |-> {"c1"}, rk |-> "none",
             rev |-> {}, hard |-> {}, recorded |-> FALSE,
             nid |-> 0, nb |-> [i \in 1..MaxNonce |-> NoTimer], nu |-> {},
             uf |-> 0, obs |-> {}, detLeft |-> NoTimer, totLeft |-> TTotal ]

Init == ss = InitRec /\ adm = {}

\* @type: $rec => Bool;
ExhR(r) == r.K /= {} /\ r.K \subseteq r.rev
Live == ss.life = "Active"
Active == Live /\ ~ExhR(ss)
\* @type: $rec => Set(Int);
LiveSet(r) == {i \in 1..MaxNonce : i <= r.nid /\ r.nb[i] > 0 /\ i \notin r.nu}

\* @type: (Str, $sig, Int, Str) => Bool;
Verifies(key, sg, claimed, pre) ==
    sg.by = key /\ sg.nonce = claimed /\ sg.pre = pre

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
    /\ adm' = adm

Challenge ==
    /\ Active /\ ss.nid < MaxNonce
    /\ Cardinality(LiveSet(ss)) < LiveLimit
    /\ ss' = [ss EXCEPT !.nid = @ + 1, !.nb[ss.nid + 1] = TNonce]
    /\ adm' = adm

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
           na == [src |-> src, sg |-> [by |-> key, nonce |-> claimed, pre |-> "ok"]]
       IN IF ~recorded
          THEN ss' = [ss EXCEPT !.obs = o] /\ adm' = adm
          ELSE IF accept /\ r.att = "Att"
          THEN /\ ss' = [ss EXCEPT !.n = @ + 1, !.C = @ \cup {key},
                         !.nu = @ \cup {claimed}, !.uf = ufn, !.obs = o]
               /\ adm' = adm \cup {na}
          ELSE IF accept /\ r.att = "Det"
          THEN /\ ss' = [ss EXCEPT !.n = @ + 1, !.att = "Res", !.rk = key,
                         !.recorded = FALSE, !.detLeft = NoTimer,
                         !.nu = @ \cup {claimed}, !.uf = ufn, !.obs = o]
               /\ adm' = adm \cup {na}
          ELSE /\ ss' = [ss EXCEPT !.n = @ + 1, !.nu = spent, !.uf = ufn, !.obs = o]
               /\ adm' = adm

\* @type: (Str, Str) => Bool;
AddClient(c, d) ==
    /\ Active /\ ss.att = "Att" /\ c \in ss.C \ ss.rev /\ d \notin ss.K
    /\ d \in Clients
    /\ ss' = [ss EXCEPT !.n = @ + 1, !.K = @ \cup {d}]
    /\ adm' = adm

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
    /\ adm' = adm

CompleteResume ==
    /\ Active /\ ss.att = "Res"
    /\ ss' = [ss EXCEPT !.n = @ + 1, !.att = "Att", !.C = {ss.rk}, !.rk = "none"]
    /\ adm' = adm

Timeout ==
    /\ Live /\ ss.att = "Det" /\ (ss.detLeft = 0 \/ ss.totLeft = 0)
    /\ ss' = [ss EXCEPT !.n = @ + 1, !.life = "Terminated"]
    /\ adm' = adm

Terminate ==
    /\ Active
    /\ ss' = [ss EXCEPT !.n = @ + 1, !.life = "Terminated"]
    /\ adm' = adm

Tick ==
    /\ IF ss.life = "Terminated" THEN ss' = ss
       ELSE ss' = [ss EXCEPT
              !.detLeft = IF @ > 0 THEN @ - 1 ELSE @,
              !.totLeft = IF ss.att = "Det" /\ @ > 0 THEN @ - 1 ELSE @,
              !.nb = [i \in 1..MaxNonce |-> IF ss.nb[i] > 0 THEN ss.nb[i] - 1 ELSE ss.nb[i]]]
    /\ adm' = adm

Restart ==
    /\ IF ss.life = "Terminated" THEN ss' = ss
       ELSE ss' = [ss EXCEPT !.att = "Det", !.detLeft = TDetach, !.C = {},
                   !.rk = "none", !.uf = 0, !.recorded = TRUE, !.n = @ + 3,
                   !.nb = [i \in 1..MaxNonce |-> NoTimer]]
    /\ adm' = adm

Next ==
    \/ Tick \/ Restart \/ Challenge \/ CompleteResume \/ Timeout \/ Terminate
    \/ \E c \in Clients : Disconnect(c)
    \/ \E c, d \in Clients : AddClient(c, d)
    \/ \E c \in Clients, w \in {"rotation", "compromise"} : Revoke(c, w)
    \/ \E key \in Clients, claimed \in 1..MaxNonce, pre \in {"ok", "bad"},
          keep \in BOOLEAN :
          claimed <= ss.nid /\
          Present("honest", keep, key, [by |-> key, nonce |-> claimed, pre |-> pre],
                  claimed, pre)
    \/ \E key \in Clients \cup AdvKeys, claimed \in 0..MaxNonce, pre \in {"ok", "bad"},
          by \in AdvKeys, sg \in ss.obs :
          AttackOn /\
          (Present("adv", FALSE, key, [by |-> by, nonce |-> claimed, pre |-> pre], claimed, pre)
           \/ Present("adv", FALSE, key, sg, claimed, pre))

(***************************************************************************)
(* Invariants                                                              *)
(***************************************************************************)
TypeOK ==
    /\ ss.att \in {"Att", "Det", "Res"} /\ ss.life \in {"Active", "Terminated"}
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
    /\ ss.totLeft >= 0 /\ ss.totLeft <= TTotal
    /\ \A a \in adm : a.src \in {"honest", "adv"}

I9 == \A i \in 1..MaxNonce : ss.nb[i] >= NoTimer /\ ss.nb[i] <= TNonce
IBook == Cardinality(LiveSet(ss)) <= LiveLimit
IFail == ss.uf <= FailMax
I15 == Live =>
    /\ ss.C \subseteq ss.K
    /\ (ss.att = "Att") <=> (ss.C /= {})
    /\ (ss.att = "Res") <=> (ss.rk /= "none")
    /\ ss.rk /= "none" => ss.rk \in ss.K
IRev == ss.C \cap ss.hard = {} /\ ss.rk \notin ss.hard
Timers == Live => ((ss.att = "Det") <=> (ss.detLeft /= NoTimer))

\* The unforgeability consequence: only keys of Clients are ever registered,
\* because the attacker holds no key of Clients (AdvKeys and Clients disjoint).
KeysHonest == ss.K \subseteq Clients /\ ss.K \cap AdvKeys = {}

\* NoForgery as a state invariant: every admission was built by an honest
\* client, or carries a signature the attacker observed.
NoForgery == \A a \in adm : a.src = "honest" \/ a.sg \in ss.obs

Inv == TypeOK /\ I9 /\ IBook /\ IFail /\ I15 /\ IRev /\ Timers /\ KeysHonest /\ NoForgery
\* Inductive step: start from any state satisfying Inv (and the constants'
\* assumptions), take one Next step, ask that Inv still holds.
\* AdvKeys and Clients are disjoint by CInit.
\* Gen(k) draws an arbitrary value whose sets have at most k elements; the
\* universes of client keys and nonces are no larger than that, so only adm
\* (a ghost set) is cut: admissions beyond the cut are not examined.
\* Non-vacuity: checking this as an invariant of IndInit (length 0) must FAIL,
\* i.e. Inv is satisfiable with a resuming session and an attacker admission.
Witness == ~(ss.att = "Res" /\ ss.life = "Active" /\ \E a \in adm : a.src = "adv")
IndInit == ss = Gen(4) /\ adm = Gen(8) /\ Inv
=============================================================================
