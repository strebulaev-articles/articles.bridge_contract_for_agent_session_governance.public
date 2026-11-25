------------------------------ MODULE BridgeProofI3 ------------------------------
(***************************************************************************)
(* TLAPS spike on the model (BridgeContractTP.tla, derived mechanically    *)
(* from BridgeContract.tla by make-tp-model.sh): Init => Shape, and         *)
(* Shape /\ [Next]_vars => Shape', where Shape gives every session record  *)
(* its fields and a scope within Perms (I3).  Actions are proved one by    *)
(* one; the status of each is in the log.                                  *)
(***************************************************************************)
EXTENDS BridgeContractTP, TLAPS

Fields == {"att", "hum", "life", "n", "K", "C", "rk", "rev", "hard", "recorded",
           "nid", "nb", "nk", "ng", "nu", "nr", "uf", "obs", "detLeft", "humLeft",
           "scope", "ver", "queue", "callLeft", "used", "ans", "appr", "drained",
           "held", "opd", "dlv", "sent", "totLeft", "quar", "endWhy", "corrupt"}

Shape == /\ DOMAIN ss = Sessions
         /\ \A s \in Sessions : DOMAIN ss[s] = Fields /\ ss[s].scope \subseteq Perms

THEOREM InitShape == Init => Shape
<1> SUFFICES ASSUME Init PROVE Shape OBVIOUS
<1>1. DOMAIN InitRec = Fields
  BY DEF InitRec, Fields
<1>2. InitRec.scope = Perms
  BY DEF InitRec
<1> QED BY <1>1, <1>2 DEF Init, Shape

\* Step keeps the fields, and the scope within Perms when the update does.
LEMMA StepShape ==
  ASSUME Shape, NEW s \in Sessions, NEW k, NEW u,
         DOMAIN u \subseteq Fields,
         "scope" \in DOMAIN u => u.scope \subseteq Perms,
         Step(s, k, u)
  PROVE  Shape'
<1> DEFINE r  == ss[s]
<1> DEFINE m1 == [n |-> r.n + k] @@ u
<1> DEFINE r2 == m1 @@ r
<1>0. "n" \in Fields
  BY DEF Fields
<1>1. DOMAIN m1 = {"n"} \cup DOMAIN u
  BY DEF @@
<1>2. DOMAIN r2 = Fields
  BY <1>0, <1>1 DEF @@, Shape
<1>3. r2.scope \subseteq Perms
  BY <1>1 DEF @@, Shape, Fields
<1>4. ss' = [ss EXCEPT ![s] = r2]
  BY DEF Step
<1> QED BY <1>2, <1>3, <1>4 DEF Shape

\* The fields obs and nr are replaced (the proof that works for Corrupt).
LEMMA ObsNrSet ==
  ASSUME Shape, NEW s \in Sessions, NEW v, NEW w,
         ss' = [ss EXCEPT ![s].obs = v, ![s].nr = w]
  PROVE  Shape'
BY DEF Shape, Fields

\* Actions whose update is a literal record: the domain and scope facts are
\* checked on the literal.
LEMMA EscalateShape == ASSUME Shape, NEW s \in Sessions, Escalate(s) PROVE Shape'
<1> USE DEF Escalate
<1> DEFINE r == ss[s]
<1> DEFINE u1 == [hum |-> "Pend", humLeft |-> IF r.hum = "None" THEN THuman ELSE r.humLeft]
<1>1. DOMAIN u1 \subseteq Fields /\ ("scope" \in DOMAIN u1 => u1.scope \subseteq Perms)
  BY DEF Fields
<1>2. Step(s, 1, u1)
  OBVIOUS
<1> QED BY <1>1, <1>2, StepShape

LEMMA ResolveShape == ASSUME Shape, NEW s \in Sessions, Resolve(s) PROVE Shape'
<1> USE DEF Resolve
<1> DEFINE r == ss[s]
<1> DEFINE u1 == [hum |-> "None", humLeft |-> NoTimer,
                  appr |-> [k \in Keys |->
                              IF k \in r.queue \ r.held /\ r.appr[k] = NoTimer
                              THEN TApprove ELSE r.appr[k]]]
<1>1. DOMAIN u1 \subseteq Fields /\ ("scope" \in DOMAIN u1 => u1.scope \subseteq Perms)
  BY DEF Fields
<1>2. Step(s, 1, u1)
  OBVIOUS
<1> QED BY <1>1, <1>2, StepShape

LEMMA NarrowShape == ASSUME Shape, NEW s \in Sessions, NEW ns, Narrow(s, ns) PROVE Shape'
<1> USE DEF Narrow
<1> DEFINE u1 == [scope |-> ns, ver |-> ss[s].ver + 1]
<1>1. DOMAIN u1 \subseteq Fields /\ ("scope" \in DOMAIN u1 => u1.scope \subseteq Perms)
  BY DEF Fields, Shape
<1>2. Step(s, 1, u1)
  OBVIOUS
<1> QED BY <1>1, <1>2, StepShape

LEMMA TickRecKeeps ==
  ASSUME NEW r, DOMAIN r = Fields, r.scope \subseteq Perms
  PROVE  DOMAIN TickRec(r) = Fields /\ TickRec(r).scope \subseteq Perms
<1>1. CASE r.life = "Terminated" \/ r.quar
  BY <1>1 DEF TickRec
<1>2. CASE ~(r.life = "Terminated" \/ r.quar)
  <2>1. TickRec(r) = [r EXCEPT
            !.detLeft = IF @ > 0 THEN @ - 1 ELSE @,
            !.totLeft = IF r.att = "Det" /\ @ > 0 THEN @ - 1 ELSE @,
            !.humLeft = IF @ > 0 THEN @ - 1 ELSE @,
            !.nb = [i \in 1..MaxNonce |-> IF @[i] > 0 THEN @[i] - 1 ELSE @[i]],
            !.appr = [k \in Keys |-> IF @[k] > 0 THEN @[k] - 1 ELSE @[k]],
            !.callLeft = [k \in Keys |->
                IF k \in r.queue /\ r.callLeft[k] > 0
                THEN r.callLeft[k] - 1 ELSE r.callLeft[k]]]
    BY <1>2 DEF TickRec
  <2> QED BY <2>1 DEF Fields
<1> QED BY <1>1, <1>2

LEMMA TickShape == ASSUME Shape, Tick PROVE Shape'
BY TickRecKeeps DEF Tick, Shape

\* Hard cases, tried with the same tools: the update is chosen by an IF/branch.
LEMMA DisconnectShape == ASSUME Shape, NEW s \in Sessions, NEW c, Disconnect(s, c) PROVE Shape'
<1> USE DEF Disconnect
<1>1. CASE ss[s].att = "Att" /\ c \in ss[s].C /\ ss[s].C # {c}
  <2> DEFINE u1 == [C |-> ss[s].C \ {c}]
  <2>1. DOMAIN u1 \subseteq Fields BY DEF Fields
  <2> QED BY <1>1, <2>1, StepShape
<1>2. CASE ss[s].att = "Att" /\ ss[s].C = {c}
  <2> DEFINE u2 == [att |-> "Det", C |-> {}, detLeft |-> TDetach] @@ Rec
  <2>1. DOMAIN u2 \subseteq Fields BY DEF Fields, Rec, @@
  <2>2. "scope" \notin DOMAIN u2 BY DEF Rec, @@
  <2> QED BY <1>2, <2>1, <2>2, StepShape
<1>3. CASE ss[s].att = "Res" /\ ss[s].rk = c
  <2> DEFINE u3 == [att |-> "Det", rk |-> "none", detLeft |-> TDetach] @@ Rec
  <2>1. DOMAIN u3 \subseteq Fields BY DEF Fields, Rec, @@
  <2>2. "scope" \notin DOMAIN u3 BY DEF Rec, @@
  <2> QED BY <1>3, <2>1, <2>2, StepShape
<1> QED BY <1>1, <1>2, <1>3

\* The attacker's entry point: three Step branches and one plain EXCEPT.
LEMMA PresentShape ==
  ASSUME Shape, NEW s \in Sessions, NEW src, NEW keep, NEW key, NEW sig,
         NEW claimed, NEW pre, Present(s, src, keep, key, sig, claimed, pre)
  PROVE  Shape'
<1> USE DEF Present
<1> DEFINE r == ss[s]
<1> DEFINE issued == claimed \in 1..r.nid
<1> DEFINE bound == issued /\ r.nk[claimed] = key /\ r.ng[claimed]
<1> DEFINE known == key \in r.K /\ Verifies(key, sig, claimed, pre) /\ bound
<1> DEFINE live == issued /\ r.nb[claimed] > 0 /\ claimed \notin r.nu
<1> DEFINE accept == (known /\ key \notin r.rev) /\ live /\ pre = "ok" /\ r.att # "Res"
<1> DEFINE recorded == known \/ r.uf < FailMax
<1> DEFINE ufn == IF known THEN 0 ELSE r.uf + 1
<1> DEFINE o == IF src = "honest" /\ keep /\ AttackOn /\ Cardinality(r.obs) < ObsMax
                THEN r.obs \cup {[by |-> key, nonce |-> claimed, pre |-> pre]}
                ELSE r.obs
<1> DEFINE wf == issued /\ pre = "ok" /\ key \in Clients
                 /\ Verifies(key, sig, claimed, pre)
<1> DEFINE nrn == IF wf /\ ~accept
                  THEN [r.nr EXCEPT ![claimed] = @ \cup {key}] ELSE r.nr
<1>1. CASE ~recorded
  <2>1. ss' = [ss EXCEPT ![s].obs = o, ![s].nr = nrn]
    BY <1>1
  <2> QED BY <2>1, ObsNrSet
<1>2. CASE recorded /\ accept /\ r.att = "Att"
  <2> DEFINE u == [C |-> r.C \cup {key}, nu |-> r.nu \cup {claimed}, uf |-> ufn, obs |-> o]
  <2>1. DOMAIN u \subseteq Fields BY DEF Fields
  <2> QED BY <1>2, <2>1, StepShape
<1>3. CASE recorded /\ accept /\ r.att = "Det"
  <2> DEFINE u == [att |-> "Res", rk |-> key, recorded |-> FALSE, detLeft |-> NoTimer,
                   nu |-> r.nu \cup {claimed}, uf |-> ufn, obs |-> o]
  <2>1. DOMAIN u \subseteq Fields BY DEF Fields
  <2> QED BY <1>3, <2>1, StepShape
<1>4. CASE recorded /\ ~(accept /\ r.att = "Att") /\ ~(accept /\ r.att = "Det")
  <2> DEFINE u == [nu |-> r.nu \cup (IF known THEN {claimed} ELSE {}),
                   uf |-> ufn, obs |-> o, nr |-> nrn]
  <2>1. DOMAIN u \subseteq Fields BY DEF Fields
  <2> QED BY <1>4, <2>1, StepShape
<1> QED BY <1>1, <1>2, <1>3, <1>4

LEMMA CorruptShape == ASSUME Shape, NEW s \in Sessions, Corrupt(s) PROVE Shape'
BY DEF Corrupt, Shape, Fields

=============================================================================
