---- MODULE BridgeContractTP ----
(***************************************************************************)
(* TLA+ model of the Bridge Contract.                                      *)
(*                                                                         *)
(* The state space is the product machine of the paper (Section 5.1):      *)
(*   attachment {Att, Det, Res} x human {None, Pend} x lifecycle           *)
(*   {Active, Terminated}                                                  *)
(* with the narrow-only authority scope (I3, I10), a client set (I15),    *)
(* challenge-response re-attach with an abstract proof of possession, a    *)
(* single-use nonce bound to a key id and a prefix check (I4, I8, I9,      *)
(* I11), durable append and restart recovery (I12), the tool queue (I13)   *)
(* and answer binding (I14).                                               *)
(*                                                                         *)
(* Abstractions (each is also stated in README.md):                        *)
(*  - The event log is represented by its length n and by the state it     *)
(*    determines.  A transition appends its events and changes the state   *)
(*    in ONE step (the committed batch of I12, taken as atomic); a crash   *)
(*    between the append and the in-memory change is equivalent to the     *)
(*    same step followed by Restart, which rebuilds everything from the    *)
(*    log.  A crash inside a batch is not modelled.                        *)
(*  - Hash chain and cryptography are not modelled as bytes.  A signature   *)
(*    is a record (signing key, signed nonce, signed prefix verdict); it   *)
(*    verifies iff the signing key is the key the request names and the    *)
(*    signed fields match the request (Verifies, the unforgeability       *)
(*    assumption UF).  A request authenticates iff its key is registered,  *)
(*    its signature verifies and the nonce it names was issued for that    *)
(*    key while the key was registered and not revoked.  Who can produce a *)
(*    signature is the attacker model: an honest client signs with a key   *)
(*    in Clients; the attacker signs only with AdvKeys, which it holds,    *)
(*    and replays signatures it observed (obs).  It sees the log and the   *)
(*    wire, replays, reorders (stale nonces), submits with keys it does    *)
(*    not hold, asks for challenges under any key id, and never obtains a  *)
(*    key of Clients.                                                      *)
(*    The nonce book holds the nonces issued, each with the key id it was  *)
(*    issued for; a nonce is live iff it is issued, unexpired and unspent; *)
(*    at most LiveLimit are live, and a challenge is refused when the book *)
(*    is full (I11f).  A challenge is answered the same way for every key  *)
(*    id.  A failure before authentication is recorded only while fewer    *)
(*    than FailMax were recorded since the last request that               *)
(*    authenticated (I11g).  Corrupt stands for tampering with the stored  *)
(*    log (I5).                                                            *)
(*  - Issuing a challenge is not an event; nonces are volatile (a restart  *)
(*    voids them).  The replay of the unseen events is not modelled; the   *)
(*    Python suite and the shared vectors check it.                        *)
(*  - Time is a set of countdowns decremented by Tick (no wall clock).     *)
(*                                                                         *)
(* Also modelled: quarantine on a chain failure (rule Q: RESUME_FAILED and *)
(* RECOVERY_FAILED freeze the session, nothing terminates), the cumulative *)
(* detachment cap T_total (a countdown that runs only in Det and is never   *)
(* reset), the detached-call policy (refuse, queue, forward) for calls     *)
(* with no escalation pending while no client is attached, a call with no  *)
(* escalation pending while a client is attached (it goes straight to the  *)
(* runtime when the scope permits it and is refused and recorded when it   *)
(* does not), the forwarding acknowledgement (TOOL_CALL_DELIVERED; a       *)
(* drained call that is not delivered is forwarded again after a restart)  *)
(* and the effects of termination (the queue is discarded, no timer is     *)
(* left).  Not modelled: TOOL_CALL_COMPLETED (it changes no state) and     *)
(* bridge downtime (time does not pass during Restart, so the cap counts   *)
(* no downtime here and no timer elapses during a restart).                *)
(*                                                                         *)
(* Invariant names match the paper (I1..I15).                              *)
(***************************************************************************)
EXTENDS Naturals, Integers, FiniteSets, TLAPS

\* The TLC module's f @@ g: g's pairs where f has none (defined here, TLAPS has no TLC).
f @@ g == [x \in (DOMAIN f) \cup (DOMAIN g) |-> IF x \in DOMAIN f THEN f[x] ELSE g[x]]

CONSTANTS
    Sessions,        \* session identifiers
    Clients,         \* client keys; "c1" is registered at attach (I15)
    Perms,           \* permissions; the scope at attach is all of Perms
    Keys,            \* idempotency keys of tool calls (I13)
    TDetach,         \* T_detach, in ticks
    THuman,          \* T_human
    TNonce,          \* T_nonce, lifetime of a challenge nonce (I9)
    MaxNonce,        \* bound on challenges per session (model bound)
    AdvKeys,         \* signing keys the attacker holds (disjoint from Clients)
    AttackOn,        \* BOOLEAN: the attacker acts (model switch; see README)
    ObsMax,          \* most signatures the attacker remembers (model bound)
    LiveLimit,       \* most live nonces per session (I11f; the references use 16)
    FailMax,         \* most unauthenticated failures recorded per period (I11g)
    TTotal,          \* T_total, cap on the time spent detached, over all episodes
    DetPolicy,       \* "refuse", "queue" or "forward": calls away with h = None
    Allow,           \* permissions that "forward" may run without the client
    TCall,           \* T_call, lifetime of a queued call
    TApprove,        \* T_approve, validity of a human approval
    QMax,            \* maximum queue size
    MaxEvents,       \* bound on state-growing actions (model bound)
    MaxRestarts,     \* bound on bridge restarts (model bound)
    AllowFaults,     \* BOOLEAN: log tampering and recovery faults
    GhostOn          \* BOOLEAN: the ghost `last` is written (model switch; see README)

ASSUME TCall <= THuman /\ TDetach <= TTotal   \* the timer bounds are a MUST
ASSUME DetPolicy \in {"refuse", "queue", "forward"} /\ Allow \subseteq {"p1", "p2"}
ASSUME Cardinality(Perms) >= 1 /\ QMax >= 1 /\ TNonce >= 1
ASSUME "c1" \in Clients
ASSUME AdvKeys \cap Clients = {} /\ LiveLimit >= 1 /\ FailMax >= 1
ASSUME AttackOn \in BOOLEAN /\ ObsMax \in Nat /\ GhostOn \in BOOLEAN

VARIABLES
    ss,              \* ss[s]: the record of session s (see InitRec)
    fwd,             \* fwd[s]: calls forwarded to the runtime (external)
    restarts,        \* number of bridge restarts so far
    last             \* ghost: the last request answered.  A presentation (auth,
                     \* live, pre, known, rec, src) or a call with no escalation
                     \* pending (call, fw), and the session it went to (sid)

vars == <<ss, fwd, restarts, last>>

NoTimer == -1
Min(a, b) == IF a < b THEN a ELSE b
MaxVer == Cardinality(Perms)

\* The permission a queued call needs (calls are "k1" and "k2").
Need(k) == IF k = "k1" THEN "p1" ELSE "p2"

ASSUME Keys \subseteq {"k1", "k2"} /\ Perms \subseteq {"p1", "p2"}

\* The key ids a challenge can name: the client keys and, when the attacker
\* acts, its own (a key id that no session will ever register).
KeyIds == Clients \cup (IF AttackOn THEN AdvKeys ELSE {})

(***************************************************************************)
(* Records                                                                 *)
(***************************************************************************)

InitRec ==
    [ att |-> "Att", hum |-> "None", life |-> "Active",
      n |-> 1,                              \* genesis ATTACHED
      K |-> {"c1"}, C |-> {"c1"}, rk |-> "none",   \* client set (I15)
      rev |-> {}, hard |-> {},              \* revoked keys; hard = compromise
      recorded |-> FALSE,                   \* RESUME_PREPARED of this detachment
      nid |-> 0,                            \* nonces issued: ids 1..nid
      nb |-> [i \in 1..MaxNonce |-> NoTimer],   \* nonce book: countdown per id (I9)
      nk |-> [i \in 1..MaxNonce |-> "none"],    \* the key id the nonce was issued for
      ng |-> [i \in 1..MaxNonce |-> FALSE],     \* that key was registered, unrevoked, at issue
      nu |-> {},                            \* spent nonce ids (I11d)
      nr |-> [i \in 1..MaxNonce |-> {}],    \* ghost: keys refused with this nonce
      uf |-> 0,                             \* unauthenticated failures recorded (I11g)
      obs |-> {},                           \* signatures honest clients put on the wire
      detLeft |-> NoTimer, humLeft |-> NoTimer,
      scope |-> Perms, ver |-> 0,
      queue |-> {}, callLeft |-> [k \in Keys |-> NoTimer], used |-> {},
      ans |-> [k \in Keys |-> "none"],      \* answer binding (I14)
      appr |-> [k \in Keys |-> NoTimer],    \* approval countdown of each call (I13)
      drained |-> {},
      held |-> {},                          \* queued with no escalation (G1 queue)
      opd |-> {},                           \* operator-drained in this instance
      dlv |-> {},                           \* TOOL_CALL_DELIVERED
      sent |-> {},                          \* forwarded by this bridge instance
      totLeft |-> TTotal,                   \* T_total, runs only in Det
      quar |-> FALSE, endWhy |-> "none",    \* rule Q; why the session ended
      corrupt |-> FALSE ]

Init ==
    /\ ss = [s \in Sessions |-> InitRec]
    /\ fwd = [s \in Sessions |-> {}]
    /\ restarts = 0
    /\ \E t \in Sessions :
         last = [auth |-> FALSE, live |-> FALSE, pre |-> "none",
                 known |-> FALSE, rec |-> TRUE, src |-> "honest", sid |-> t,
                 call |-> "none", fw |-> FALSE]

\* key_exhausted (I11-REVOKE): every registered key is revoked.  A side
\* predicate derived from the log, not a cell: client operations are refused
\* and only OperatorAddKey and OperatorEnd act on it, but the timers keep
\* running (Tick, Timeout), a restart treats the session like any other, and
\* a lost transport still detaches it: a detached session that is not given a
\* key terminates after T_detach (or T_total).  A challenge is still answered
\* and a request still refused: neither answer may depend on the registry.
ExhR(r) == r.K # {} /\ r.K \subseteq r.rev

Live(s) == ss[s].life = "Active" /\ ~ss[s].quar
Active(s) == Live(s) /\ ~ExhR(ss[s])

\* RESUME_PREPARED: the bridge's own resume record of a detachment (I1).
Rec == [ recorded |-> TRUE ]

\* The nonces that are live: issued, unexpired, unspent.
LiveSet(r) == {i \in 1..r.nid : r.nb[i] > 0 /\ i \notin r.nu}

\* The attacker model.  UF (unforgeability): a signature verifies for a
\* request only if the signing key is the key the request names and the
\* signed nonce and prefix verdict are the ones it carries; the signer must
\* hold that key.  Honest clients hold the keys in Clients and sign what they
\* present; the attacker holds AdvKeys only, and can resubmit any signature
\* it observed.  It never obtains a key in Clients.
Verifies(key, sig, claimed, pre) ==
    sig.by = key /\ sig.nonce = claimed /\ sig.pre = pre
\* The signatures the attacker can make for a request that carries this nonce
\* and verdict: with its own keys only.  (A signature that does not match the
\* request does not verify, whoever made it; one canonical mismatch per
\* request is enough, and the observed signatures below cover the replays.)
AdvSigs(claimed, pre) == [by : AdvKeys, nonce : {claimed}, pre : {pre}]

\* Append k events and update the record in one committed step.
Step(s, k, u) ==
    ss' = [ss EXCEPT ![s] = ([n |-> ss[s].n + k] @@ u) @@ ss[s]]

Room(s, k) == ss[s].n + k <= MaxEvents

\* TERMINATION and its effects (Section 5.1): the queue is discarded, no
\* timer is left running and the nonces are void.
End(why) ==
    [ life |-> "Terminated", endWhy |-> why,
      queue |-> {}, held |-> {},
      callLeft |-> [k \in Keys |-> NoTimer],
      appr |-> [k \in Keys |-> NoTimer],
      ans |-> [k \in Keys |-> "none"],
      detLeft |-> NoTimer, humLeft |-> NoTimer,
      nb |-> [i \in 1..MaxNonce |-> NoTimer] ]

(***************************************************************************)
(* Actions                                                                 *)
(***************************************************************************)

\* Transport loss of client c.  While others remain connected it is
\* CLIENT_LEFT and the cell does not change (I15b); the last departure, or
\* that of the re-attaching client, is (Att|Res, h) -> (Det, h):
\* DETACHMENT, RESUME_PREPARED (I1).
Disconnect(s, c) ==
    /\ Live(s) /\ Room(s, 2)
    /\ \/ ss[s].att = "Att" /\ c \in ss[s].C /\ ss[s].C # {c}
          /\ Step(s, 1, [C |-> ss[s].C \ {c}])
       \/ ss[s].att = "Att" /\ ss[s].C = {c}
          /\ Step(s, 2, [att |-> "Det", C |-> {}, detLeft |-> TDetach] @@ Rec)
       \/ ss[s].att = "Res" /\ ss[s].rk = c
          /\ Step(s, 2, [att |-> "Det", rk |-> "none",
                         detLeft |-> TDetach] @@ Rec)
    /\ UNCHANGED <<fwd, restarts, last>>

\* (a, None|Pend) -> (a, Pend): HUMAN_PENDING.
Escalate(s) ==
    /\ Active(s) /\ Room(s, 1)
    /\ LET r == ss[s]
           u1 == [hum |-> "Pend",
                  humLeft |-> IF r.hum = "None" THEN THuman ELSE r.humLeft]
       IN Step(s, 1, u1)
    /\ UNCHANGED <<fwd, restarts, last>>

\* (a, Pend) -> (a, None): HUMAN_RESOLVED.  The timeout wins: a resolve in the
\* tick in which T_human has run out is refused (humLeft = 0).  The approval of every call
\* queued during this escalation starts here, one countdown per call; a call
\* that already has one (an earlier escalation) keeps it.
\* The queue does not drain here (Rule D): see Drain.
Resolve(s) ==
    /\ Active(s) /\ ss[s].hum = "Pend" /\ ss[s].humLeft > 0 /\ Room(s, 1)
    /\ LET r == ss[s]
           u1 == [hum |-> "None", humLeft |-> NoTimer,
                  appr |-> [k \in Keys |->
                              IF k \in r.queue \ r.held /\ r.appr[k] = NoTimer
                              THEN TApprove ELSE r.appr[k]]]
       IN Step(s, 1, u1)
    /\ UNCHANGED <<fwd, restarts, last>>

\* I2, I13: a call arriving while Human = Pend is queued, or rejected when
\* the queue is full.  Nothing is forwarded here.
Submit(s, k) ==
    /\ Active(s) /\ ss[s].hum = "Pend" /\ k \notin ss[s].used /\ Room(s, 1)
    /\ LET r == ss[s] IN
       IF Cardinality(r.queue) < QMax
       THEN Step(s, 1, [queue |-> r.queue \cup {k},
                        callLeft |-> [r.callLeft EXCEPT ![k] = TCall],
                        used |-> r.used \cup {k}])
       ELSE Step(s, 1, [used |-> r.used \cup {k}])    \* TOOL_CALL_REJECTED
    /\ UNCHANGED <<fwd, restarts, last>>

\* I13: a queued call outlives T_call: TOOL_CALL_EXPIRED.
ExpireCall(s, k) ==
    /\ Active(s) /\ k \in ss[s].queue /\ ss[s].callLeft[k] = 0
    /\ Step(s, 1, [queue |-> ss[s].queue \ {k}, held |-> ss[s].held \ {k},
                   callLeft |-> [ss[s].callLeft EXCEPT ![k] = NoTimer],
                   appr |-> [ss[s].appr EXCEPT ![k] = NoTimer],
                   ans |-> [ss[s].ans EXCEPT ![k] = "none"]])
    /\ UNCHANGED <<fwd, restarts, last>>

\* I14: the human answers a queued call; "ok" means the hash of what the
\* client displayed equals the hash recorded at queue time, "bad" that it
\* differs, "deny" that the human refused.  The first answer is final.
Answer(s, k, a) ==
    /\ Active(s) /\ k \in ss[s].queue /\ ss[s].ans[k] = "none" /\ Room(s, 1)
    /\ Step(s, 1, [ans |-> [ss[s].ans EXCEPT ![k] = a]])
    /\ UNCHANGED <<fwd, restarts, last>>

\* G1 (policy queue or forward): a call arrives with h = None while no client
\* is attached.  refuse: nothing happens (the action is disabled).  queue: the
\* call is held for an answer.  forward: an allowlisted, in-scope call is
\* recorded as queued, answered and drained (three events) and may be
\* forwarded at once.
SubmitAway(s, k) ==
    /\ DetPolicy # "refuse"
    /\ Active(s) /\ ss[s].hum = "None" /\ ss[s].att # "Att"
    /\ k \notin ss[s].used /\ Need(k) \in ss[s].scope
    /\ LET r == ss[s] IN
       IF DetPolicy = "queue"
       THEN /\ Room(s, 1)
            /\ IF Cardinality(r.queue) < QMax
               THEN Step(s, 1, [queue |-> r.queue \cup {k}, held |-> r.held \cup {k},
                                callLeft |-> [r.callLeft EXCEPT ![k] = TCall],
                                used |-> r.used \cup {k}])
               ELSE Step(s, 1, [used |-> r.used \cup {k}])
       ELSE /\ Need(k) \in Allow /\ Room(s, 3)
            /\ Step(s, 3, [drained |-> r.drained \cup {k}, opd |-> r.opd \cup {k},
                           used |-> r.used \cup {k}])
    /\ UNCHANGED <<fwd, restarts, last>>

\* A call arrives in (Att, None), with no escalation pending.  It is not
\* queued and takes no key.  Inside the current scope it goes straight to
\* the runtime and leaves no event, so the session record does not change.
\* Outside the scope it is refused and recorded (TOOL_CALL_REJECTED, reason
\* scope) and nothing is sent.  The ghost `last` notes which of the two
\* happened (fw), and for which call.
Direct(s, k) ==
    /\ Active(s) /\ ss[s].att = "Att" /\ ss[s].hum = "None"
    /\ k \notin ss[s].used
    /\ LET inscope == Need(k) \in ss[s].scope IN
         /\ IF inscope THEN UNCHANGED ss
                       ELSE Room(s, 1) /\ Step(s, 1, [life |-> "Active"])
         /\ last' = IF GhostOn
                    THEN [auth |-> FALSE, live |-> FALSE, pre |-> "none",
                          known |-> FALSE, rec |-> TRUE, src |-> "honest",
                          sid |-> s, call |-> k, fw |-> inscope]
                    ELSE last
    /\ UNCHANGED <<fwd, restarts>>

\* Rule D + I13 + I14: drain in (Att, None), revalidating each call against
\* the current scope, its own lifetime, its approval and its answer.  One
\* event per call.  A held call that is unanswered and in time waits; a held
\* call needs no escalation approval.
Drain(s) ==
    /\ Active(s) /\ ss[s].att = "Att" /\ ss[s].hum = "None"
    /\ ss[s].queue # {}
    /\ LET r == ss[s]
           wait == {k \in r.queue : /\ k \in r.held /\ r.ans[k] = "none"
                                    /\ r.callLeft[k] > 0}
           proc == r.queue \ wait
           ok == {k \in proc : /\ r.callLeft[k] > 0
                               /\ (r.appr[k] > 0 \/ k \in r.held)
                               /\ r.ans[k] = "ok"
                               /\ Need(k) \in r.scope}
       IN /\ proc # {}
          /\ Step(s, Cardinality(proc),
                  [queue |-> wait, held |-> r.held \cap wait,
                   drained |-> r.drained \cup ok,
                   callLeft |-> [k \in Keys |-> IF k \in wait THEN r.callLeft[k] ELSE NoTimer],
                   appr |-> [k \in Keys |-> IF k \in wait THEN r.appr[k] ELSE NoTimer],
                   ans |-> [k \in Keys |-> IF k \in wait THEN r.ans[k] ELSE "none"]])
    /\ UNCHANGED <<fwd, restarts, last>>

\* I12: a drained call is forwarded only after its DRAINED event is committed,
\* in (Att, None) (or, for an operator-drained call, while h = None), and once
\* per bridge instance; a call whose delivery was acknowledged is never
\* forwarded again.  After a restart `sent` is empty, so an undelivered call
\* is forwarded again.
Forward(s, k) ==
    /\ Active(s) /\ k \in ss[s].drained /\ k \notin ss[s].dlv
    /\ k \notin ss[s].sent
    /\ ss[s].hum = "None"
    /\ \/ ss[s].att = "Att"
       \/ k \in ss[s].opd
    /\ fwd' = [fwd EXCEPT ![s] = @ \cup {k}]
    /\ ss' = [ss EXCEPT ![s].sent = @ \cup {k}]
    /\ UNCHANGED <<restarts, last>>

\* TOOL_CALL_DELIVERED: the runtime acknowledges a forwarded call.
Deliver(s, k) ==
    /\ Active(s) /\ k \in fwd[s] /\ k \in ss[s].drained /\ k \notin ss[s].dlv
    /\ Room(s, 1)
    /\ Step(s, 1, [dlv |-> ss[s].dlv \cup {k}])
    /\ UNCHANGED <<fwd, restarts, last>>

\* I3, I10: narrowing is allowed in every cell; the version advances.
Narrow(s, ns) ==
    /\ Active(s) /\ ns \subseteq ss[s].scope /\ ns # ss[s].scope
    /\ ss[s].ver < MaxVer /\ Room(s, 1)
    /\ Step(s, 1, [scope |-> ns, ver |-> ss[s].ver + 1])
    /\ UNCHANGED <<fwd, restarts, last>>

\* I3: a widening proposal, in any cell, is rejected and changes nothing.
Extend(s, ns) ==
    /\ Active(s) /\ ~(ns \subseteq ss[s].scope) /\ Room(s, 1)
    /\ Step(s, 1, [life |-> "Active"])      \* AUTHORITY_EXTENSION_REJECTED
    /\ UNCHANGED <<fwd, restarts, last>>

\* Someone asks for a challenge under the key id kid (I11b): a fresh nonce,
\* valid for T_nonce, unused, bound to kid.  The answer is the same for every
\* key id, registered or not: the guard does not read kid, and what differs
\* is only the bridge's own note of whether kid was a registered, unrevoked
\* key at this moment (ng).  Not a governance event, so n does not change.
Challenge(s, kid) ==
    /\ Live(s) /\ ss[s].nid < MaxNonce
    /\ Cardinality(LiveSet(ss[s])) < LiveLimit     \* full book: refused (I11f)
    /\ LET i == ss[s].nid + 1 IN
       ss' = [ss EXCEPT ![s].nid = i,
                         ![s].nb = [@ EXCEPT ![i] = TNonce],
                         ![s].nk = [@ EXCEPT ![i] = kid],
                         ![s].ng = [@ EXCEPT ![i] = kid \in ss[s].K \ ss[s].rev]]
    /\ UNCHANGED <<fwd, restarts, last>>

\* A re-attach or join request (key, sig, claimed nonce id, prefix verdict).
\* It authenticates (known) iff the key is registered, the signature
\* verifies and the nonce it names was issued for this key while the key
\* was registered and unrevoked (I11c): a nonce issued for a key that was
\* not registered then never authenticates a request, whatever the registry
\* becomes, and a nonce issued for one key authenticates no other.  It is
\* authentic iff it authenticates and the key is not revoked (I11-REVOKE).
\* A request that does not authenticate is RESUME_REJECTED and does not touch
\* the nonce; one that authenticates consumes its nonce (I11d), also when it
\* is refused (revoked key, stale nonce, bad prefix, another request being
\* verified).  An authentic one is accepted only if the nonce is live (I9,
\* I11b), the history is a prefix (I4) and no other request is being
\* verified.  Accepted: Att -> a join (CLIENT_JOINED), Det -> Res
\* (RESUME_STARTED).  Rejection never changes the cell (I11e).
\* A failure before authentication is recorded only while fewer than FailMax
\* were recorded since the last request that authenticated; otherwise it
\* changes nothing.  A request that authenticates is always recorded and
\* restores the allowance (I11g).  src says who built the request: an honest
\* client (its signature goes on the wire, obs) or the attacker.  nr (ghost)
\* notes each refused request under a client key that carries a matching
\* signature and an "ok" verdict: the requests a later presentation of the
\* same bytes would repeat.  (A request under a key of the attacker is not
\* noted: such a key is never registered, K is within Clients.)
Present(s, src, keep, key, sig, claimed, pre) ==
    /\ Live(s)
    /\ LET r == ss[s]
           issued == claimed \in 1..r.nid
           bound == issued /\ r.nk[claimed] = key /\ r.ng[claimed]
           known == key \in r.K /\ Verifies(key, sig, claimed, pre) /\ bound
           authentic == known /\ key \notin r.rev
           live == issued /\ r.nb[claimed] > 0 /\ claimed \notin r.nu
           accept == authentic /\ live /\ pre = "ok" /\ r.att # "Res"
           spent == r.nu \cup (IF known THEN {claimed} ELSE {})
           recorded == known \/ r.uf < FailMax
           ufn == IF known THEN 0 ELSE r.uf + 1
           o == IF src = "honest" /\ keep /\ AttackOn /\ Cardinality(r.obs) < ObsMax
                THEN r.obs \cup {[by |-> key, nonce |-> claimed, pre |-> pre]}
                ELSE r.obs
           wf == issued /\ pre = "ok" /\ key \in Clients
                 /\ Verifies(key, sig, claimed, pre)
           nrn == IF wf /\ ~accept
                  THEN [r.nr EXCEPT ![claimed] = @ \cup {key}] ELSE r.nr
       IN /\ last' = IF GhostOn
                      THEN [auth |-> authentic, live |-> live, pre |-> pre,
                            known |-> known, rec |-> recorded, src |-> src,
                            sid |-> s, call |-> "none", fw |-> FALSE]
                      ELSE last
          /\ IF ~recorded
             THEN ss' = [ss EXCEPT ![s].obs = o, ![s].nr = nrn]
             ELSE /\ Room(s, 1)
                  /\ IF accept /\ r.att = "Att"
                     THEN Step(s, 1, [C |-> r.C \cup {key}, nu |-> r.nu \cup {claimed},
                                      uf |-> ufn, obs |-> o])
                     ELSE IF accept /\ r.att = "Det"
                     THEN Step(s, 1, [att |-> "Res", rk |-> key, recorded |-> FALSE,
                                      detLeft |-> NoTimer, nu |-> r.nu \cup {claimed},
                                      uf |-> ufn, obs |-> o])
                     ELSE Step(s, 1, [nu |-> spent, uf |-> ufn, obs |-> o,
                                      nr |-> nrn])                \* RESUME_REJECTED
    /\ UNCHANGED <<fwd, restarts>>

\* An honest client presents: it signs, with its own key, the nonce and the
\* verdict it sends.
PresentHonest(s, keep, key, claimed, pre) ==
    /\ claimed <= ss[s].nid
    /\ Present(s, "honest", keep, key,
               [by |-> key, nonce |-> claimed, pre |-> pre], claimed, pre)

\* The attacker presents: under any key id, with a signature it made with a
\* key it holds or with one it observed.
PresentAdv(s, key, claimed, pre) ==
    /\ AttackOn
    /\ \E sig \in AdvSigs(claimed, pre) \cup ss[s].obs :
         Present(s, "adv", FALSE, key, sig, claimed, pre)

\* CLIENT_ADDED: a connected client registers a further key (I15d).
AddClient(s, c, d) ==
    /\ Active(s) /\ ss[s].att = "Att" /\ c \in ss[s].C \ ss[s].rev /\ d \notin ss[s].K
    /\ d \in Clients /\ Room(s, 1)
    /\ Step(s, 1, [K |-> ss[s].K \cup {d}])
    /\ UNCHANGED <<fwd, restarts, last>>

\* KEY_REVOKED (I11-REVOKE): the operator revokes a registered key.  The key
\* stays in K, marked revoked.  A re-attach that the key is verifying is
\* abandoned, whatever the reason of the revocation (Res -> Det, DETACHMENT,
\* RESUME_PREPARED).  Otherwise "compromise" (hard) revokes it for all
\* purposes, so a connected client using it is detached, and "rotation"
\* (soft) only stops new re-attach and join.  The events are KEY_REVOKED,
\* then CLIENT_LEFT, or DETACHMENT and RESUME_PREPARED when the last connected
\* client goes or a verification is abandoned.
Revoke(s, c, why) ==
    /\ Active(s) /\ c \in ss[s].K \ ss[s].rev
    /\ LET r == ss[s]
           base == [rev |-> r.rev \cup {c}]
           u0 == IF why = "compromise"
                 THEN base @@ [hard |-> r.hard \cup {c}] ELSE base
       IN IF r.att = "Res" /\ r.rk = c
          THEN Room(s, 3) /\ Step(s, 3, ([att |-> "Det", rk |-> "none", detLeft |-> TDetach] @@ u0) @@ Rec)
          ELSE IF why = "rotation"
          THEN Room(s, 1) /\ Step(s, 1, u0)
          ELSE IF r.att = "Att" /\ r.C = {c}
          THEN Room(s, 3) /\ Step(s, 3, ([C |-> {}, att |-> "Det", detLeft |-> TDetach] @@ u0) @@ Rec)
          ELSE IF r.att = "Att" /\ c \in r.C
          THEN Room(s, 2) /\ Step(s, 2, [C |-> r.C \ {c}] @@ u0)
          ELSE Room(s, 1) /\ Step(s, 1, u0)
    /\ UNCHANGED <<fwd, restarts, last>>

\* OPERATOR_ADD_KEY: the only recovery from key_exhausted.  It adds a new key;
\* revoked keys stay revoked, and a nonce issued before the key was added
\* stays as it was issued.
OperatorAddKey(s, d) ==
    /\ ss[s].life = "Active" /\ ~ss[s].quar /\ ExhR(ss[s])
    /\ d \in Clients \ ss[s].K /\ Room(s, 1)
    /\ Step(s, 1, [K |-> ss[s].K \cup {d}])
    /\ UNCHANGED <<fwd, restarts, last>>

\* (Res, h) -> (Att, h) once the hash chain verifies (RESUME_VERIFIED); the
\* re-attaching client becomes the client set.  Or RESUME_FAILED, and the
\* session is quarantined (rule Q), when the chain does not verify (I5).
CompleteResume(s) ==
    /\ Active(s) /\ ss[s].att = "Res"
    /\ IF ss[s].corrupt
       THEN Step(s, 1, [quar |-> TRUE])      \* RESUME_FAILED: rule Q
       ELSE Step(s, 1, [att |-> "Att", C |-> {ss[s].rk}, rk |-> "none"])
    /\ UNCHANGED <<fwd, restarts, last>>

\* L1, L2: T_detach and T_human expiry; both events when simultaneous.
Timeout(s) ==
    /\ Live(s)
    /\ LET r == ss[s]
           d == r.att = "Det" /\ (r.detLeft = 0 \/ r.totLeft = 0)
           h == r.hum = "Pend" /\ r.humLeft = 0
       IN /\ d \/ h
          /\ Step(s, 1 + (IF d THEN 1 ELSE 0) + (IF h THEN 1 ELSE 0),
                  End("timeout"))
    /\ UNCHANGED <<fwd, restarts, last>>

\* Clean end of session or abort.
Terminate(s) ==
    /\ Active(s)
    /\ Step(s, 1, End("clean"))
    /\ UNCHANGED <<fwd, restarts, last>>

\* An operator ends a quarantined or key-exhausted session (OPERATOR_TERMINATION;
\* the only way out of rule Q, and the alternative to OperatorAddKey).
OperatorEnd(s) ==
    /\ ss[s].life = "Active" /\ (ss[s].quar \/ ExhR(ss[s])) /\ Room(s, 1)
    /\ Step(s, 1, End("operator"))
    /\ UNCHANGED <<fwd, restarts, last>>

\* Environment: tampering with the stored log (detected by I5 at the next
\* verification).
Corrupt(s) ==
    /\ AllowFaults /\ Active(s) /\ ~ss[s].corrupt
    /\ ss' = [ss EXCEPT ![s].corrupt = TRUE]
    /\ UNCHANGED <<fwd, restarts, last>>

TickRec(r) ==
    IF r.life = "Terminated" \/ r.quar THEN r
    ELSE [r EXCEPT
            !.detLeft = IF @ > 0 THEN @ - 1 ELSE @,
            !.totLeft = IF r.att = "Det" /\ @ > 0 THEN @ - 1 ELSE @,
            !.humLeft = IF @ > 0 THEN @ - 1 ELSE @,
            !.nb = [i \in 1..MaxNonce |-> IF @[i] > 0 THEN @[i] - 1 ELSE @[i]],
            !.appr = [k \in Keys |-> IF @[k] > 0 THEN @[k] - 1 ELSE @[k]],
            !.callLeft = [k \in Keys |->
                IF k \in r.queue /\ r.callLeft[k] > 0
                THEN r.callLeft[k] - 1 ELSE r.callLeft[k]]]

\* One unit of time passes for every session.
Tick ==
    /\ ss' = [s \in Sessions |-> TickRec(ss[s])]
    /\ UNCHANGED <<fwd, restarts, last>>

\* The RESTART transition: bridge restart (Section 5.5).  Every active session is recovered by log
\* replay: all transports are gone, so the cell becomes (Det, h) with
\* BRIDGE_RECOVERED, DETACHMENT, RESUME_PREPARED and T_detach restarting; the
\* client set is empty and every nonce is void, with what the book held about
\* it.  A session whose log does not verify, or that suffers a recovery fault
\* (e.g. the key registry is unavailable), is quarantined with
\* RECOVERY_FAILED (rule Q).  T_detach restarts; the cumulative cap does not.
Restart ==
    /\ restarts < MaxRestarts
    /\ \E F \in SUBSET Sessions :
         /\ (~AllowFaults => F = {})
         /\ ss' = [s \in Sessions |->
              LET r == ss[s]
                  r2 == [r EXCEPT !.att = "Det", !.detLeft = TDetach,
                                  !.C = {}, !.rk = "none", !.opd = {},
                                  !.sent = {}, !.uf = 0,
                                  !.nb = [i \in 1..MaxNonce |-> NoTimer],
                                  !.nk = [i \in 1..MaxNonce |-> "none"],
                                  !.ng = [i \in 1..MaxNonce |-> FALSE],
                                  !.nr = [i \in 1..MaxNonce |-> {}]]
              IN IF r.life = "Terminated" \/ r.quar THEN r
                 ELSE IF s \in F \/ r.corrupt
                      THEN [r EXCEPT !.quar = TRUE, !.n = @ + 1]   \* RECOVERY_FAILED
                      ELSE Rec @@ [r2 EXCEPT !.n = @ + 3]]
    /\ restarts' = restarts + 1
    /\ UNCHANGED <<fwd, last>>

Next ==
    \/ Tick
    \/ Restart
    \/ \E s \in Sessions :
         \/ Escalate(s) \/ Resolve(s) \/ CompleteResume(s)
         \/ Timeout(s) \/ Terminate(s) \/ Corrupt(s) \/ Drain(s)
         \/ OperatorEnd(s)
         \/ \E kid \in KeyIds : Challenge(s, kid)
         \/ \E c \in Clients, w \in {"rotation", "compromise"} : Revoke(s, c, w)
         \/ \E d \in Clients : OperatorAddKey(s, d)
         \/ \E c \in Clients : Disconnect(s, c)
         \/ \E c, d \in Clients : AddClient(s, c, d)
         \/ \E k \in Keys : Submit(s, k) \/ ExpireCall(s, k) \/ Forward(s, k)
                          \/ SubmitAway(s, k) \/ Deliver(s, k) \/ Direct(s, k)
         \/ \E k \in Keys, a \in {"ok", "bad", "deny"} : Answer(s, k, a)
         \/ \E ns \in SUBSET Perms : Narrow(s, ns) \/ Extend(s, ns)
         \/ \E key \in Clients, claimed \in 1..MaxNonce, pre \in {"ok", "bad"},
               keep \in (IF AttackOn THEN BOOLEAN ELSE {FALSE}) :
            PresentHonest(s, keep, key, claimed, pre)
         \/ \E key \in Clients \cup AdvKeys, claimed \in 0..MaxNonce,
               pre \in {"ok", "bad"} :
            PresentAdv(s, key, claimed, pre)

Spec == Init /\ [][Next]_vars

\* Fair scheduling of the timers and of verification (axiom A6).
FairSpec == Spec /\ WF_vars(Tick)
            /\ \A s \in Sessions : WF_vars(Timeout(s)) /\ WF_vars(CompleteResume(s))

(***************************************************************************)
(* Safety: state invariants                                                *)
(***************************************************************************)

CellOf(r) == <<r.att, r.hum, r.life, r.scope, r.ver, r.queue, r.drained,
               r.K, r.C, r.rk, r.ans, r.quar, r.rev, r.hard>>

TypeOK ==
    \A s \in Sessions :
      LET r == ss[s] IN
        /\ r.att \in {"Att", "Det", "Res"} /\ r.hum \in {"None", "Pend"}
        /\ r.life \in {"Active", "Terminated"}
        /\ r.scope \subseteq Perms /\ r.queue \subseteq Keys
        /\ r.K \subseteq Clients /\ r.C \subseteq Clients
        /\ r.rev \subseteq r.K /\ r.hard \subseteq r.rev
        /\ r.rk \in Clients \cup {"none"} /\ fwd[s] \subseteq Keys
        /\ r.ans \in [Keys -> {"none", "ok", "bad", "deny"}]
        /\ r.nu \subseteq 1..r.nid /\ r.nid <= MaxNonce /\ r.uf \in Nat
        /\ r.nk \in [1..MaxNonce -> KeyIds \cup {"none"}]
        /\ r.ng \in [1..MaxNonce -> BOOLEAN]
        /\ r.nr \in [1..MaxNonce -> SUBSET Clients]
        /\ r.obs \subseteq [by : Clients, nonce : 1..MaxNonce, pre : {"ok", "bad"}]
        /\ Cardinality(r.obs) <= ObsMax /\ (~AttackOn => r.obs = {})
        /\ r.quar \in BOOLEAN /\ r.totLeft \in 0..TTotal
        /\ r.endWhy \in {"none", "timeout", "clean", "operator"}
        /\ r.appr \in [Keys -> NoTimer..TApprove]
        /\ r.held \subseteq r.queue /\ r.opd \subseteq r.drained
        /\ r.dlv \subseteq r.drained /\ r.sent \subseteq r.drained
        /\ r.used \subseteq Keys

\* I1: a detached session has the resume record of its detachment.
I1 == \A s \in Sessions : (Live(s) /\ ss[s].att = "Det") => ss[s].recorded

\* I2, I12: nothing is forwarded unless its DRAINED event is committed, and
\* drains happen only through Rule D (see the action property RuleD).
I2 == \A s \in Sessions : fwd[s] \subseteq ss[s].drained

\* Forwarding acknowledgement: only a forwarded call is delivered.
Ack == \A s \in Sessions : ss[s].dlv \subseteq fwd[s]

\* A session ends only for a stated cause: never because a chain failed
\* (rule Q).
EndCause == \A s \in Sessions :
              (ss[s].life = "Terminated") => ss[s].endWhy # "none"

\* I10: a version above 0 means a strict narrowing happened.  (That the
\* scope stays within the scope at attach is a type bound, in TypeOK; I3 is
\* the step property SP_Scope.)
I10 == \A s \in Sessions : (ss[s].ver = 0) <=> (ss[s].scope = Perms)

\* I9: a nonce never outlives T_nonce.
I9 == \A s \in Sessions : \A i \in 1..MaxNonce :
        ss[s].nb[i] >= NoTimer /\ ss[s].nb[i] <= TNonce

\* I11 (f): the nonce book is bounded; (g): unauthenticated failures are
\* recorded only up to FailMax per period (the allowance is restored by a
\* request that authenticates: step property SP_Fail).
IBook == \A s \in Sessions : Cardinality(LiveSet(ss[s])) <= LiveLimit
IFail == \A s \in Sessions : ss[s].uf <= FailMax

\* I11, the nonce is bound to a key id at issue.  A nonce is marked good only
\* for a key that was registered when it was issued.  While a good nonce is
\* live, no request naming it under its key was refused and none was seen on
\* the wire (such a request authenticates, and so spends the nonce).  What
\* was refused or seen names an issued nonce.  And a challenge is answered
\* the same way whatever key id it names.
I11 == \A s \in Sessions :
         LET r == ss[s] IN
           /\ \A i \in 1..r.nid :
                /\ r.ng[i] => r.nk[i] \in r.K
                /\ (i \in LiveSet(r) /\ r.ng[i]) =>
                     /\ r.nk[i] \notin r.nr[i]
                     /\ \A o \in r.obs : ~(o.nonce = i /\ o.by = r.nk[i])
           /\ \A i \in 1..MaxNonce : i > r.nid => r.nr[i] = {}
           /\ \A o \in r.obs : o.nonce <= r.nid
           /\ \A a, b \in KeyIds :
                ENABLED Challenge(s, a) => ENABLED Challenge(s, b)

\* I15: the client set is within the registered keys and determines the
\* attachment: Att iff someone is connected; Res and Det have nobody
\* connected, and only Res has a key being verified.
I15 == \A s \in Sessions : Live(s) =>
         /\ ss[s].C \subseteq ss[s].K
         /\ (ss[s].att = "Att") <=> (ss[s].C # {})
         /\ (ss[s].att = "Res") <=> (ss[s].rk # "none")
         /\ ss[s].rk # "none" => ss[s].rk \in ss[s].K

\* I13: queue bound, keys unique, queue and drained disjoint.
I13 == \A s \in Sessions :
         /\ Cardinality(ss[s].queue) <= QMax
         /\ ss[s].queue \subseteq ss[s].used
         /\ ss[s].drained \subseteq ss[s].used
         /\ ss[s].queue \cap ss[s].drained = {}

\* Timers run exactly in the cells of Section 5.4: T_detach in Det, T_human
\* while an escalation is pending, T_call for each queued call, and the
\* approval countdown for each call that was queued during an escalation and
\* whose escalation is resolved.  And a timer that has run out is acted on:
\* the timeout is due as soon as T_detach, the cap T_total or T_human is used
\* up (with SP_Timeout, which forbids an earlier one, this fixes when a
\* session may end by timeout; how soon it does is the liveness part).
Timers == \A s \in Sessions : Live(s) =>
            /\ (ss[s].att = "Det") <=> (ss[s].detLeft # NoTimer)
            /\ (ss[s].hum = "Pend") <=> (ss[s].humLeft # NoTimer)
            /\ \A k \in Keys :
                 /\ (k \in ss[s].queue) <=> (ss[s].callLeft[k] # NoTimer)
                 /\ (ss[s].appr[k] # NoTimer) => (k \in ss[s].queue \ ss[s].held)
                 /\ (ss[s].hum = "None" /\ k \in ss[s].queue \ ss[s].held)
                      => (ss[s].appr[k] # NoTimer)
            /\ ((ss[s].att = "Det" /\ (ss[s].detLeft = 0 \/ ss[s].totLeft = 0))
                \/ (ss[s].hum = "Pend" /\ ss[s].humLeft = 0))
                 => ENABLED Timeout(s)

\* I6: a terminated session has no queue obligation and no live timer: the
\* queue is discarded, no countdown is left and no nonce is live.
I6 == \A s \in Sessions : ss[s].life = "Terminated" =>
        /\ ss[s].queue = {}
        /\ ss[s].detLeft = NoTimer /\ ss[s].humLeft = NoTimer
        /\ \A k \in Keys : ss[s].callLeft[k] = NoTimer /\ ss[s].appr[k] = NoTimer
        /\ LiveSet(ss[s]) = {}

\* I11-REVOKE: a key revoked for compromise is not connected, and a revoked
\* key, whatever the reason, is not being verified.  (A softly revoked key
\* may stay connected.)
IRev == \A s \in Sessions :
          /\ ss[s].C \cap ss[s].hard = {}
          /\ ss[s].rk \notin ss[s].rev

Inv == TypeOK /\ I1 /\ I2 /\ Ack /\ EndCause /\ I9 /\ I10 /\ I13
       /\ IBook /\ IFail /\ I11
       /\ I15 /\ IRev /\ Timers /\ I6

(***************************************************************************)
(* Safety: properties of single steps (checked as PROPERTY [][...]_vars).  *)
(* Each rule is an operator over one session, so that a run can check one  *)
(* rule alone and say which rule a step broke (tlc_mutants.py).            *)
(***************************************************************************)

\* A re-attach starts (-> Res) or a client joins (the connected set grows).
Enters(s) == \/ (ss[s].att # "Res" /\ ss'[s].att = "Res")
             \/ (ss[s].att = "Att" /\ ss'[s].att = "Att"
                 /\ (ss'[s].C \ ss[s].C) # {})
\* The key that does so.
Entered(s) == IF ss[s].att # "Res" /\ ss'[s].att = "Res"
              THEN {ss'[s].rk} ELSE ss'[s].C \ ss[s].C

SP_I6(s) == ss[s].life = "Terminated" => ss'[s] = ss[s]

SP_Scope(s) == ss'[s].scope \subseteq ss[s].scope

SP_Version(s) ==
    /\ (ss'[s].ver = ss[s].ver + 1) <=> (ss'[s].scope # ss[s].scope)
    /\ (ss'[s].ver = ss[s].ver \/ ss'[s].ver = ss[s].ver + 1)

SP_I7(s) == CellOf(ss'[s]) # CellOf(ss[s]) => ss'[s].n > ss[s].n

SP_Enter(s) ==
    Enters(s) =>
      /\ last'.auth /\ last'.live /\ last'.pre = "ok"
      /\ \E i \in ss'[s].nu \ ss[s].nu :
           /\ i \in 1..ss[s].nid /\ ss[s].nb[i] > 0
           /\ ss[s].ng[i] /\ Entered(s) = {ss[s].nk[i]}

SP_Honest(s) == Enters(s) => last'.src = "honest"

SP_NoReplay(s) ==
    Enters(s) =>
      \A i \in ss'[s].nu \ ss[s].nu : Entered(s) \cap ss[s].nr[i] = {}

SP_Fail(s) ==
    (last'.sid = s /\ last'.known) => (last'.rec /\ ss'[s].uf = 0)

SP_Spent(s) == ss[s].nu \subseteq ss'[s].nu

SP_Issue(s) ==
    ss'[s].nid # ss[s].nid =>
      /\ LiveSet(ss[s]) \subseteq LiveSet(ss'[s])
      /\ ss'[s].nid = ss[s].nid + 1
      /\ ss'[s].nb[ss'[s].nid] = TNonce /\ ss'[s].nid \notin ss'[s].nu

SP_Chain(s) == (ss[s].att # "Att" /\ ss'[s].att = "Att") => ~ss[s].corrupt

SP_Drain(s) ==
    \A k \in ss'[s].drained \ ss[s].drained :
      /\ ss[s].hum = "None" /\ Need(k) \in ss[s].scope
      /\ \/ k \in ss'[s].opd
         \/ /\ ss[s].att = "Att"
            /\ ss[s].callLeft[k] > 0
            /\ (ss[s].appr[k] > 0 \/ k \in ss[s].held)
            /\ ss[s].ans[k] = "ok"

SP_Appr(s) ==
    \A k \in Keys :
      (ss[s].appr[k] # NoTimer /\ ss'[s].appr[k] # NoTimer)
        => ss'[s].appr[k] <= ss[s].appr[k]

SP_Direct(s) ==
    (last' # last /\ last'.sid = s /\ last'.call # "none") =>
      /\ ss[s].att = "Att" /\ ss[s].hum = "None"
      /\ IF last'.fw
         THEN Need(last'.call) \in ss[s].scope /\ ss'[s] = ss[s]
         ELSE Need(last'.call) \notin ss[s].scope /\ ss'[s].n > ss[s].n

SP_Forward(s) ==
    \A k \in ss'[s].sent \ ss[s].sent :
      /\ ss[s].hum = "None" /\ k \notin ss[s].dlv
      /\ (ss[s].att = "Att" \/ k \in ss[s].opd)

SP_Quarantine(s) ==
    ss[s].quar => (ss'[s] = ss[s] \/ ss'[s].endWhy = "operator")

SP_Total(s) ==
    /\ ss'[s].totLeft <= ss[s].totLeft
    /\ (ss'[s].totLeft < ss[s].totLeft => ss[s].att = "Det")

SP_Timeout(s) ==
    /\ (ss'[s].endWhy = "timeout" /\ ss[s].endWhy # "timeout") =>
         \/ (ss[s].att = "Det" /\ (ss[s].detLeft = 0 \/ ss[s].totLeft = 0))
         \/ (ss[s].hum = "Pend" /\ ss[s].humLeft = 0)
    \* the timeout wins over a resolve in the tick of T_human
    /\ (ss[s].hum = "Pend" /\ ss'[s].hum = "None") => ss[s].humLeft # 0

SP_Allow(s) == \A k \in ss'[s].opd \ ss[s].opd : Need(k) \in Allow

SP_Register(s) ==
    ss'[s].K # ss[s].K =>
      \/ ExhR(ss[s])
      \/ (ss[s].att = "Att" /\ (ss[s].C \ ss[s].rev) # {})

SP_Revoke(s) ==
    /\ ss[s].K \subseteq ss'[s].K /\ ss[s].rev \subseteq ss'[s].rev
    /\ ss[s].hard \subseteq ss'[s].hard

SP_Join(s) ==
    (ss[s].att = "Att" /\ ss'[s].att = "Att") =>
      ((ss'[s].C \ ss[s].C) \cap ss[s].rev = {})

SP_Exhausted(s) ==
    ExhR(ss[s]) =>
      \/ ss'[s] = ss[s]
      \/ ss'[s].endWhy \in {"operator", "timeout"}
      \/ ((ss'[s].K \ ss[s].K) # {} /\ ss'[s].rev = ss[s].rev
          /\ ss'[s].att = ss[s].att /\ ss'[s].life = "Active")
      \/ (ss'[s].life = "Active" /\ ss'[s].K = ss[s].K
          /\ ss'[s].rev = ss[s].rev /\ ss'[s].scope = ss[s].scope
          /\ ss'[s].queue = ss[s].queue /\ ss'[s].drained = ss[s].drained
          /\ ss'[s].ans = ss[s].ans /\ ss'[s].hum = ss[s].hum
          /\ ss'[s].used = ss[s].used
          /\ ss'[s].C \subseteq ss[s].C
          /\ (ss'[s].att # ss[s].att => ss'[s].att = "Det"))

SP_Shrink(s) ==
    (ss[s].att = "Att" /\ ss'[s].C \subseteq ss[s].C /\ ss'[s].C # ss[s].C /\ ss'[s].C # {}) =>
      ss'[s].att = "Att"

SP_LeaveDet(s) ==
    (ss[s].att = "Det" /\ ss'[s].att # "Det") =>
      (ss'[s].att = "Res" \/ ss'[s].life = "Terminated")

StepProps ==
  [][ \A s \in Sessions :
      /\ \* I6: nothing about a terminated session ever changes again
         SP_I6(s)
      /\ \* I3: scope only narrows, in every cell
         SP_Scope(s)
      /\ \* I10: version +1 exactly when the scope strictly narrows
         SP_Version(s)
      /\ \* I7: the cell changes only together with new committed events
         SP_I7(s)
      /\ \* I4, I9, I11, I15: entering Res, or adding a connected client, needs
         \* an authentic request with a live, unused nonce and a prefix; the
         \* nonce is spent by it, and it was issued for the key that enters,
         \* while that key was registered and unrevoked
         SP_Enter(s)
      /\ \* I11, honest presenter: every accepted re-attach or join was
         \* presented by an honest client, never by the attacker (who can
         \* replay what it observed)
         SP_Honest(s)
      /\ \* I11, no replay: a request that was presented and refused is never
         \* accepted later, whoever presents it again and whatever the key
         \* registry has become
         SP_NoReplay(s)
      /\ \* I11g: a request that authenticates is always recorded and restores
         \* the allowance of the session that received it (the checks on the
         \* last presentation are steps, so that `last` can stay out of the
         \* VIEW)
         SP_Fail(s)
      /\ \* I11d: a nonce once spent stays spent until a new one is issued
         SP_Spent(s)
      /\ \* I11f: issuing a challenge never invalidates a live nonce, and the
         \* nonce it issues is live for T_nonce whatever key id it names
         SP_Issue(s)
      /\ \* I5: verification succeeds only on an intact chain
         SP_Chain(s)
      /\ \* Rule D, I13: calls drain only in (Att, None) (the operator's
         \* allowlist excepted), and only calls that are in time, approved
         \* (a held call by its own answer) and permitted by the current scope
         SP_Drain(s)
      /\ \* I13, approval: the approval of a call is recorded once and only
         \* runs down; a later resolution does not renew it
         SP_Appr(s)
      /\ \* I3, direct calls: a call with no escalation pending goes straight
         \* to the runtime only in (Att, None) and only within the current
         \* scope; outside the scope it is refused, and the refusal is an
         \* event
         SP_Direct(s)
      /\ \* I2, I12: forwarding only while h = None, in Att or (for an
         \* operator-drained call) away, after commit, and never for a call
         \* whose delivery was acknowledged
         SP_Forward(s)
      /\ \* rule Q: a quarantined session changes only by an operator's end
         SP_Quarantine(s)
      /\ \* T_total: the cumulative cap is never reset and runs down only
         \* while the session is detached
         SP_Total(s)
      /\ \* T_total, T_detach and T_human: a session ends by timeout only when
         \* one of them has run out
         SP_Timeout(s)
      /\ \* the operator's allowlist is the only way to drain away
         SP_Allow(s)
      /\ \* I15d: a key is registered only through a connected, unrevoked
         \* client, or by the operator on a key-exhausted session
         SP_Register(s)
      /\ \* I11-REVOKE: keys are never deleted and a revocation is never undone
         SP_Revoke(s)
      /\ \* I11-REVOKE: a client joining a session is not revoked
         SP_Join(s)
      /\ \* key_exhausted: no client operation is served.  The session
         \* changes only by the passing of time (timers, an expiry that ends
         \* it), a restart or a lost transport (it goes or stays detached,
         \* nothing else changes), a challenge or a refused request (the
         \* nonce book and the failure record), the operator's end, or a new
         \* key (which clears the predicate)
         SP_Exhausted(s)
      /\ \* I15b: a client set shrinking while someone stays connected does
         \* not change the attachment
         SP_Shrink(s)
      /\ \* I9/I11: a detached session leaves Det only by an authentic
         \* re-attach, a timeout, a clean end, or a restart
         SP_LeaveDet(s)
    ]_vars

(***************************************************************************)
(* Liveness (checked under FairSpec)                                       *)
(***************************************************************************)

\* L1 (per detachment episode): a detached session re-attaches, ends or is
\* quarantined (rule Q).  A key_exhausted session is no exception: its timers
\* keep running, so unless the operator adds a key it ends.
L1 == \A s \in Sessions :
        (Live(s) /\ ss[s].att = "Det")
          ~> (ss[s].att # "Det" \/ ss[s].life = "Terminated" \/ ss[s].quar)

\* L1 for the verification: a session does not stay in Res.  The re-attach
\* completes, is abandoned (the client is lost or its key revoked), or the
\* session ends or is quarantined.
L1Res == \A s \in Sessions :
           (Live(s) /\ ss[s].att = "Res")
             ~> (ss[s].att # "Res" \/ ss[s].life = "Terminated" \/ ss[s].quar)

\* L1 with the cumulative cap: once the time spent detached has used up
\* T_total, the session leaves Det (re-attach in progress) or ends.
CapEnds == \A s \in Sessions :
             (Live(s) /\ ss[s].att = "Det" /\ ss[s].totLeft = 0)
               ~> (ss[s].att # "Det" \/ ss[s].life = "Terminated" \/ ss[s].quar)

\* L2: a pending escalation is resolved or the session ends.
L2 == \A s \in Sessions :
        (Live(s) /\ ss[s].hum = "Pend")
          ~> (ss[s].hum = "None" \/ ss[s].life = "Terminated" \/ ss[s].quar)

\* The state identity for the safety configurations: `last` only records the
\* request answered by the step just taken, no guard reads it, and the checks
\* on it are steps (StepProps), so states that differ only in it have the
\* same futures.  (A call sent straight to the runtime changes nothing but
\* `last`, so the state it leads to is never a new one under the view; the
\* states TLC expands therefore never carry such a call in `last`, and the
\* step that sends one always changes `last`, which is what SP_Direct reads.)
\* What can still matter for the future of a session.  (1) A nonce that is
\* expired, voided or spent can never be live again (a timer only counts down,
\* and a challenge only sets the next id), so only the countdown of the live
\* ones tells two states apart, and the spent set not at all.  (2) The key id
\* of a nonce is read only together with its good mark, so the key id of a
\* nonce that is not good tells nothing.  (3) The refusals noted for a nonce
\* are read only when a request naming that nonce is accepted, which needs
\* the nonce live.  (4) A terminated session never changes again (Tick and
\* Restart leave it as it is), so what is left to tell apart is that it ended
\* and why, and what I6 reads of it: its queue and its timers.  (They are all
\* discarded at termination, so they add no class; they are kept so that the
\* view does not hide from I6 a session that ended with something left.)
\* The step properties are evaluated on every transition, whatever the view
\* says.
Canon(r) ==
    IF r.life = "Terminated"
    THEN [life |-> r.life, endWhy |-> r.endWhy,
          queue |-> r.queue, detLeft |-> r.detLeft, humLeft |-> r.humLeft,
          callLeft |-> r.callLeft, appr |-> r.appr, nlive |-> LiveSet(r)]
    ELSE [r EXCEPT
            !.nb = [i \in DOMAIN r.nb |->
                      IF r.nb[i] > 0 /\ i \notin r.nu THEN r.nb[i] ELSE 0],
            !.nu = {},
            !.nk = [i \in DOMAIN r.nk |->
                      IF r.ng[i] THEN r.nk[i] ELSE "none"],
            !.nr = [i \in DOMAIN r.nr |->
                      IF r.nb[i] > 0 /\ i \notin r.nu THEN r.nr[i] ELSE {}]]

SafetyView ==
    <<[s \in Sessions |-> Canon(ss[s])],
      [s \in Sessions |-> IF ss[s].life = "Terminated" THEN {} ELSE fwd[s]],
      restarts>>

\* Sessions are interchangeable (used by the safety configuration only).

=============================================================================
