#!/usr/bin/env python3
"""
Sanity check that TLC's verdict on BridgeContract.tla is not vacuous: each
mutant below breaks one rule in the spec text, and the property its label
names must then be violated.

    TLA2TOOLS=/path/to/tla2tools.jar [JAVA=java] [ONLY='part of a name|...'] python3 -I tlc_mutants.py

Attribution.  A mutant is run against the one property its label names and
nothing else: a state invariant (a conjunct of ``Inv``), a rule of
``StepProps`` (an operator ``SP_x``; the script appends
``Only_SP_x == [][\\A s \\in Sessions : SP_x(s)]_vars`` to the copy of the
module and checks that) or a liveness property.  It is killed only when TLC
reports a violation and the property TLC names is that one; "No error has
been found" is a survivor; a violation of anything else, a parse or semantic
error, a crash or a timeout is an ERROR and never a kill.  With DIAGNOSE=1 a
survivor is run once more against every property, listed one by one, so the
log says what would have caught it.

Control.  For every configuration a mutant uses, the unmodified spec is run
first with all the properties of that configuration (``Inv`` and
``StepProps``, or the liveness properties) and must end with "No error has
been found"; otherwise the verdicts in that configuration would be vacuous
and the script stops.

    python3 -I tlc_mutants.py --check-patches   # no TLC: every anchor applies
                                                # exactly once, every label names
                                                # a property of the spec, every
                                                # property has a mutant, and the
                                                # verdict logic is self-tested
    python3 -I tlc_mutants.py --list            # the mutants, labels and configurations
"""
import hashlib
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
JAVA = os.environ.get("JAVA", "java")
JAR = os.environ.get("TLA2TOOLS")
ONLY = [o for o in os.environ.get("ONLY", "").split("|") if o]   # name filter
WORKERS = os.environ.get("WORKERS", "auto")
TIMEOUT = int(os.environ.get("TLC_TIMEOUT", "3600"))             # seconds, per run
DIAGNOSE = os.environ.get("DIAGNOSE") == "1"

# Configurations: replacements applied to the base configuration (the text of
# BridgeContract.cfg with one session, no symmetry and MaxEvents = 6).
# narrow: one permission, one call key, no log tampering
NARROW = {'Perms = {"p1", "p2"}': 'Perms = {"p1"}',
          'Keys = {"k1", "k2"}': 'Keys = {"k1"}',
          "AllowFaults = TRUE": "AllowFaults = FALSE"}
Q = {**NARROW, 'DetPolicy = "refuse"': 'DetPolicy = "queue"'}
FWD = {'DetPolicy = "refuse"': 'DetPolicy = "forward"'}
# forward, narrow, one event more: a detachment, a call drained away, its delivery
FWD7 = {**NARROW, **FWD, "MaxEvents = 6": "MaxEvents = 7"}
# deep and narrow: one client, one call key, one challenge; enough events for
# forward, deliver, restart, re-attach and forward again
DEEP = {**NARROW, **FWD, "MaxEvents = 6": "MaxEvents = 11",
        'Clients = {"c1", "c2"}': 'Clients = {"c1"}', "MaxNonce = 2": "MaxNonce = 1"}
# the attacker on (the base configuration has it off); its presentations
# multiply the transitions, so one event less
ATK = {**NARROW, "AttackOn = FALSE": "AttackOn = TRUE", "ObsMax = 0": "ObsMax = 2",
       "MaxEvents = 6": "MaxEvents = 5"}
# three client keys: one to revoke, one to stay, one to register
C3 = {**NARROW, 'Clients = {"c1", "c2"}': 'Clients = {"c1", "c2", "c3"}',
      "MaxEvents = 6": "MaxEvents = 5"}
# more than one live nonce, and more challenges than the limit
BOOK = {**NARROW, "LiveLimit = 1": "LiveLimit = 2", "MaxNonce = 2": "MaxNonce = 3",
        "MaxEvents = 6": "MaxEvents = 4"}
# two events more, narrow, one client key: a re-attach, a second request
# refused while it is verified, the verification abandoned, the request again
N8 = {**NARROW, "MaxEvents = 6": "MaxEvents = 8",
      'Clients = {"c1", "c2"}': 'Clients = {"c1"}'}
# liveness: fair scheduling with the liveness properties instead of the safety
# ones, no view, and the ghost off (the liveness properties do not read it)
LIVE = {"SPECIFICATION Spec": "SPECIFICATION FairSpec", "VIEW SafetyView\n": "",
        "INVARIANT Inv\n": "", "GhostOn = TRUE": "GhostOn = FALSE",
        "PROPERTY StepProps": "PROPERTY L1\nPROPERTY L1Res\nPROPERTY L2\nPROPERTY CapEnds",
        "MaxEvents = 6": "MaxEvents = 5"}
BASE = {}
CONFIG_NAMES = [("base", BASE), ("queue", Q), ("forward", FWD), ("forward7", FWD7),
                ("deep", DEEP), ("attacker", ATK), ("clients3", C3), ("book", BOOK),
                ("narrow8", N8), ("live", LIVE)]

# Properties that are implied by another one and so cannot have a mutant of
# their own: name -> reason.
NO_OWN_MUTANT = {
    "CapEnds": "implied by L1 (same consequent, stronger antecedent); the cap is "
               "enforced by the last conjunct of Timers",
}

# (name, property that must be violated, old text, new text[, configuration])
MUTANTS = [
    ("I1 detach without a resume record", "I1",
     "/\\ Step(s, 2, [att |-> \"Det\", C |-> {}, detLeft |-> TDetach] @@ Rec)",
     "/\\ Step(s, 2, [att |-> \"Det\", C |-> {}, detLeft |-> TDetach])"),
    ("I1 restart without a resume record", "I1",
     "ELSE Rec @@ [r2 EXCEPT !.n = @ + 3]]",
     "ELSE [r2 EXCEPT !.n = @ + 3]]"),
    ("I10 narrowing without version bump", "I10",
     "Step(s, 1, [scope |-> ns, ver |-> ss[s].ver + 1])",
     "Step(s, 1, [scope |-> ns, ver |-> ss[s].ver])"),
    ("I10 the version advances without a narrowing", "SP_Version",
     "/\\ Active(s) /\\ ~(ns \\subseteq ss[s].scope) /\\ Room(s, 1)\n    /\\ Step(s, 1, [life |-> \"Active\"])",
     "/\\ Active(s) /\\ ~(ns \\subseteq ss[s].scope) /\\ Room(s, 1)\n    /\\ Step(s, 1, [ver |-> ss[s].ver + 1])"),
    ("I3 widening applied", "SP_Scope",
     "/\\ Active(s) /\\ ~(ns \\subseteq ss[s].scope) /\\ Room(s, 1)\n    /\\ Step(s, 1, [life |-> \"Active\"])",
     "/\\ Active(s) /\\ ~(ns \\subseteq ss[s].scope) /\\ Room(s, 1)\n    /\\ Step(s, 1, [scope |-> ns])"),
    ("I3 a direct call outside the scope is forwarded", "SP_Direct",
     "LET inscope == Need(k) \\in ss[s].scope IN",
     "LET inscope == TRUE IN"),
    ("I3 a direct call outside the scope is refused without a record", "SP_Direct",
     "ELSE Room(s, 1) /\\ Step(s, 1, [life |-> \"Active\"])",
     "ELSE UNCHANGED ss"),
    ("I7 cell change without an event", "SP_I7",
     "Step(s, k, u) ==\n    ss' = [ss EXCEPT ![s] = ([n |-> ss[s].n + k] @@ u) @@ ss[s]]",
     "Step(s, k, u) ==\n    ss' = [ss EXCEPT ![s] = ([n |-> ss[s].n] @@ u) @@ ss[s]]"),
    ("I11 an unauthentic request is accepted", "SP_Enter",
     "accept == authentic /\\ live /\\ pre = \"ok\" /\\ r.att # \"Res\"",
     "accept == live /\\ pre = \"ok\" /\\ r.att # \"Res\""),
    ("I9 an expired nonce is accepted", "SP_Enter",
     "live == issued /\\ r.nb[claimed] > 0 /\\ claimed \\notin r.nu",
     "live == issued /\\ claimed \\notin r.nu"),
    ("I9 a nonce outlives T_nonce", "I9",
     "![s].nb = [@ EXCEPT ![i] = TNonce],",
     "![s].nb = [@ EXCEPT ![i] = TNonce + 1],"),
    ("I11 a spent nonce is accepted again", "SP_Enter",
     "live == issued /\\ r.nb[claimed] > 0 /\\ claimed \\notin r.nu",
     "live == issued /\\ r.nb[claimed] > 0"),
    ("I11 an accepted nonce is not consumed", "SP_Enter",
     "THEN Step(s, 1, [C |-> r.C \\cup {key}, nu |-> r.nu \\cup {claimed},",
     "THEN Step(s, 1, [C |-> r.C \\cup {key}, nu |-> r.nu,"),
    ("I4 the prefix is not checked", "SP_Enter",
     "accept == authentic /\\ live /\\ pre = \"ok\" /\\ r.att # \"Res\"",
     "accept == authentic /\\ live /\\ r.att # \"Res\""),
    # the nonce is bound to a key id at issue
    ("I11 a nonce issued for an unregistered key is marked good", "I11",
     "![s].ng = [@ EXCEPT ![i] = kid \\in ss[s].K \\ ss[s].rev]]",
     "![s].ng = [@ EXCEPT ![i] = TRUE]]"),
    ("I11 a challenge is refused for an unregistered key", "I11",
     "    /\\ Live(s) /\\ ss[s].nid < MaxNonce\n",
     "    /\\ Live(s) /\\ kid \\in ss[s].K /\\ ss[s].nid < MaxNonce\n"),
    ("I11 a nonce issued before its key was registered verifies afterwards", "SP_NoReplay",
     "bound == issued /\\ r.nk[claimed] = key /\\ r.ng[claimed]",
     "bound == issued /\\ r.nk[claimed] = key"),
    ("I11 a replayed request is accepted once its key is registered", "SP_Honest",
     "bound == issued /\\ r.nk[claimed] = key /\\ r.ng[claimed]",
     "bound == issued /\\ r.nk[claimed] = key", ATK),
    ("I11 a nonce is accepted for a key it was not issued for", "SP_Enter",
     "bound == issued /\\ r.nk[claimed] = key /\\ r.ng[claimed]",
     "bound == issued /\\ r.ng[claimed]"),
    ("I11 CLIENT_ADDED revives the nonces issued for the new key", "SP_NoReplay",
     "    /\\ d \\in Clients /\\ Room(s, 1)\n    /\\ Step(s, 1, [K |-> ss[s].K \\cup {d}])",
     "    /\\ d \\in Clients /\\ Room(s, 1)\n    /\\ Step(s, 1, [K |-> ss[s].K \\cup {d},\n"
     "                    ng |-> [i \\in 1..MaxNonce |-> ss[s].ng[i] \\/ ss[s].nk[i] = d]])"),
    ("I11 OPERATOR_ADD_KEY revives the nonces issued for the new key", "SP_NoReplay",
     "    /\\ d \\in Clients \\ ss[s].K /\\ Room(s, 1)\n    /\\ Step(s, 1, [K |-> ss[s].K \\cup {d}])",
     "    /\\ d \\in Clients \\ ss[s].K /\\ Room(s, 1)\n    /\\ Step(s, 1, [K |-> ss[s].K \\cup {d},\n"
     "                    ng |-> [i \\in 1..MaxNonce |-> ss[s].ng[i] \\/ ss[s].nk[i] = d]])"),
    ("I11 a request refused during a verification keeps its nonce", "SP_NoReplay",
     "spent == r.nu \\cup (IF known THEN {claimed} ELSE {})",
     "spent == r.nu", N8),
    ("I11 a restart forgets which nonces were spent", "SP_Spent",
     "!.sent = {}, !.uf = 0,",
     "!.sent = {}, !.uf = 0, !.nu = {},"),
    ("I11 a detached session is attached without a request", "SP_LeaveDet",
     "/\\ Active(s) /\\ ss[s].att = \"Res\"",
     "/\\ Active(s) /\\ ss[s].att # \"Att\""),
    ("I5 resume verifies a corrupt chain", "SP_Chain",
     "IF ss[s].corrupt\n       THEN Step(s, 1, [quar |-> TRUE])      \\* RESUME_FAILED: rule Q\n       ELSE Step(s, 1, [att |-> \"Att\", C |-> {ss[s].rk}, rk |-> \"none\"])",
     "Step(s, 1, [att |-> \"Att\", C |-> {ss[s].rk}, rk |-> \"none\"])"),
    ("Rule D: drain while detached", "SP_Drain",
     "/\\ Active(s) /\\ ss[s].att = \"Att\" /\\ ss[s].hum = \"None\"\n    /\\ ss[s].queue # {}",
     "/\\ Active(s) /\\ ss[s].hum = \"None\"\n    /\\ ss[s].queue # {}"),
    ("I13 drain skips scope revalidation", "SP_Drain",
     "/\\ Need(k) \\in r.scope}",
     "/\\ TRUE}"),
    ("I13 drain ignores approval expiry", "SP_Drain",
     "/\\ (r.appr[k] > 0 \\/ k \\in r.held)",
     "/\\ TRUE"),
    ("I13 a later resolution renews a lapsed approval", "SP_Appr",
     "IF k \\in r.queue \\ r.held /\\ r.appr[k] = NoTimer",
     "IF k \\in r.queue \\ r.held"),
    ("I14 drain ignores the answer", "SP_Drain",
     "/\\ r.ans[k] = \"ok\"",
     "/\\ TRUE"),
    ("I12 forward before the DRAINED event", "I2",
     "/\\ Active(s) /\\ k \\in ss[s].drained /\\ k \\notin ss[s].dlv",
     "/\\ Active(s) /\\ k \\in ss[s].queue /\\ k \\notin ss[s].dlv"),
    ("I13 queue bound ignored", "I13",
     "IF Cardinality(r.queue) < QMax\n       THEN Step(s, 1, [queue |-> r.queue \\cup {k},\n                        callLeft",
     "IF TRUE\n       THEN Step(s, 1, [queue |-> r.queue \\cup {k},\n                        callLeft"),
    # termination and its effects
    ("I6 a termination keeps the queue", "I6",
     "      queue |-> {}, held |-> {},\n      callLeft |-> [k \\in Keys |-> NoTimer],\n      appr |->",
     "      callLeft |-> [k \\in Keys |-> NoTimer],\n      appr |->"),
    ("I6 a termination leaves the timers set", "I6",
     "      detLeft |-> NoTimer, humLeft |-> NoTimer,\n      nb |-> [i \\in 1..MaxNonce |-> NoTimer] ]",
     "      nb |-> [i \\in 1..MaxNonce |-> NoTimer] ]"),
    ("I6 an escalation is accepted after termination", "SP_I6",
     "Escalate(s) ==\n    /\\ Active(s) /\\ Room(s, 1)",
     "Escalate(s) ==\n    /\\ (Active(s) \\/ ss[s].life = \"Terminated\") /\\ Room(s, 1)"),
    ("I6 time runs on after termination", "SP_I6",
     "IF r.life = \"Terminated\" \\/ r.quar THEN r\n    ELSE [r EXCEPT",
     "IF r.quar THEN r\n    ELSE [r EXCEPT"),
    ("Timers: T_detach not stopped in Res", "Timers",
     "[att |-> \"Res\", rk |-> key, recorded |-> FALSE,\n                                      detLeft |-> NoTimer, nu |->",
     "[att |-> \"Res\", rk |-> key, recorded |-> FALSE,\n                                      nu |->"),
    ("Timers: an expired call keeps its approval", "Timers",
     "                   appr |-> [ss[s].appr EXCEPT ![k] = NoTimer],\n",
     ""),
    ("Timers: a session times out early", "SP_Timeout",
     "d == r.att = \"Det\" /\\ (r.detLeft = 0 \\/ r.totLeft = 0)",
     "d == r.att = \"Det\""),
    ("I15 a partial departure detaches", "I15",
     "/\\ Step(s, 1, [C |-> ss[s].C \\ {c}])",
     "/\\ Step(s, 2, [att |-> \"Det\", C |-> ss[s].C \\ {c}, detLeft |-> TDetach] @@ Rec)"),
    ("I15 a partial departure leaves the attached cell", "SP_Shrink",
     "/\\ Step(s, 1, [C |-> ss[s].C \\ {c}])",
     "/\\ Step(s, 2, [att |-> \"Det\", C |-> ss[s].C \\ {c}, detLeft |-> TDetach] @@ Rec)"),
    ("I15 a key is registered without a connected client", "SP_Register",
     "/\\ Active(s) /\\ ss[s].att = \"Att\" /\\ c \\in ss[s].C \\ ss[s].rev /\\ d \\notin ss[s].K",
     "/\\ Active(s) /\\ d \\notin ss[s].K"),
    ("I15 a completed resume attaches nobody", "I15",
     "ELSE Step(s, 1, [att |-> \"Att\", C |-> {ss[s].rk}, rk |-> \"none\"])",
     "ELSE Step(s, 1, [att |-> \"Att\", C |-> {}, rk |-> \"none\"])"),
    ("I15 a restart keeps the client set", "I15",
     "!.C = {}, !.rk = \"none\", !.opd = {},\n                                  !.sent = {}, !.uf = 0,",
     "!.rk = \"none\", !.opd = {},\n                                  !.sent = {}, !.uf = 0,"),
    # attacker model: possession, forgery, replay
    ("Attacker holds a client's signing key", "SP_Honest",
     "AdvSigs(claimed, pre) == [by : AdvKeys,",
     "AdvSigs(claimed, pre) == [by : AdvKeys \\cup Clients,", ATK),
    ("Attacker: a signature verifies under any key", "SP_Honest",
     "sig.by = key /\\ sig.nonce = claimed /\\ sig.pre = pre",
     "sig.nonce = claimed /\\ sig.pre = pre", ATK),
    ("Attacker: a signature is not bound to its nonce", "SP_Honest",
     "sig.by = key /\\ sig.nonce = claimed /\\ sig.pre = pre",
     "sig.by = key /\\ sig.pre = pre", ATK),
    # I11 (f), (g): bounded nonce book, bounded unauthenticated log
    ("I11f a challenge ignores the live-nonce limit", "IBook",
     "    /\\ Cardinality(LiveSet(ss[s])) < LiveLimit     \\* full book: refused (I11f)\n",
     ""),
    ("I11f a challenge evicts a live nonce", "SP_Issue",
     "![s].nb = [@ EXCEPT ![i] = TNonce],",
     "![s].nb = [@ EXCEPT ![i] = TNonce], ![s].nu = @ \\cup LiveSet(ss[s]),", BOOK),
    ("I11f a challenge for an unregistered key issues a dead nonce", "SP_Issue",
     "![s].nb = [@ EXCEPT ![i] = TNonce],",
     "![s].nb = [@ EXCEPT ![i] = IF kid \\in ss[s].K THEN TNonce ELSE 0],"),
    ("I11g unauthenticated failures are all recorded", "IFail",
     "recorded == known \\/ r.uf < FailMax",
     "recorded == TRUE"),
    ("I11g a request that verifies is dropped past the limit", "SP_Fail",
     "recorded == known \\/ r.uf < FailMax",
     "recorded == r.uf < FailMax"),
    ("I11g an authentic request does not restore the allowance", "SP_Fail",
     "ufn == IF known THEN 0 ELSE r.uf + 1",
     "ufn == IF known THEN r.uf ELSE r.uf + 1"),
    # rule Q: quarantine
    ("Q a chain failure terminates the session", "EndCause",
     "THEN Step(s, 1, [quar |-> TRUE])      \\* RESUME_FAILED: rule Q",
     "THEN Step(s, 2, [life |-> \"Terminated\"])"),
    ("Q a recovery failure terminates the session", "EndCause",
     "THEN [r EXCEPT !.quar = TRUE, !.n = @ + 1]   \\* RECOVERY_FAILED",
     "THEN [r EXCEPT !.life = \"Terminated\", !.n = @ + 2]"),
    ("Q a quarantined session keeps ticking", "SP_Quarantine",
     "IF r.life = \"Terminated\" \\/ r.quar THEN r\n    ELSE [r EXCEPT",
     "IF r.life = \"Terminated\" THEN r\n    ELSE [r EXCEPT"),
    ("Q a restart touches a quarantined session", "SP_Quarantine",
     "IN IF r.life = \"Terminated\" \\/ r.quar THEN r",
     "IN IF r.life = \"Terminated\" THEN r"),
    # I11-REVOKE: key lifecycle
    ("I11-REVOKE a revoked key is accepted", "SP_Join",
     "authentic == known /\\ key \\notin r.rev",
     "authentic == known"),
    ("I11-REVOKE revoking a key removes it from K", "SP_Revoke",
     "base == [rev |-> r.rev \\cup {c}]",
     "base == [rev |-> r.rev \\cup {c}, K |-> r.K \\ {c}]"),
    ("I11-REVOKE a key outside K can be revoked", "TypeOK",
     "/\\ Active(s) /\\ c \\in ss[s].K \\ ss[s].rev",
     "/\\ Active(s) /\\ c \\in Clients \\ ss[s].rev"),
    ("I11-REVOKE a hard revocation leaves the client connected", "IRev",
     "THEN Room(s, 2) /\\ Step(s, 2, [C |-> r.C \\ {c}] @@ u0)",
     "THEN Room(s, 2) /\\ Step(s, 2, u0)"),
    ("I11-REVOKE revoking the last client does not detach", "I15",
     "([C |-> {}, att |-> \"Det\", detLeft |-> TDetach] @@ u0)",
     "([C |-> {}] @@ u0)"),
    ("I11-REVOKE a hard revocation does not abandon a verification", "IRev",
     "IN IF r.att = \"Res\" /\\ r.rk = c\n",
     "IN IF r.att = \"Res\" /\\ r.rk = c /\\ why = \"rotation\"\n"),
    ("I11-REVOKE a soft revocation does not abandon a verification", "IRev",
     "IN IF r.att = \"Res\" /\\ r.rk = c\n",
     "IN IF r.att = \"Res\" /\\ r.rk = c /\\ why = \"compromise\"\n"),
    ("L1 a soft revocation leaves the session in Res", "L1Res",
     "IN IF r.att = \"Res\" /\\ r.rk = c\n",
     "IN IF r.att = \"Res\" /\\ r.rk = c /\\ why = \"compromise\"\n", LIVE),
    ("I11-REVOKE a revoked client registers a key", "SP_Register",
     "c \\in ss[s].C \\ ss[s].rev /\\ d \\notin ss[s].K",
     "c \\in ss[s].C /\\ d \\notin ss[s].K", C3),
    ("key_exhausted does not freeze the session", "SP_Exhausted",
     "Active(s) == Live(s) /\\ ~ExhR(ss[s])",
     "Active(s) == Live(s)"),
    # the timers of a key_exhausted session keep running (liveness L1)
    ("key_exhausted freezes the timers", "L1",
     "IF r.life = \"Terminated\" \\/ r.quar THEN r\n    ELSE [r EXCEPT",
     "IF r.life = \"Terminated\" \\/ r.quar \\/ ExhR(r) THEN r\n    ELSE [r EXCEPT",
     LIVE),
    ("key_exhausted: a timeout does not fire", "L1",
     "Timeout(s) ==\n    /\\ Live(s)",
     "Timeout(s) ==\n    /\\ Active(s)", LIVE),
    ("L2 an escalation never times out", "L2",
     "h == r.hum = \"Pend\" /\\ r.humLeft = 0",
     "h == FALSE", LIVE),
    ("OPERATOR_ADD_KEY on a session that is not key_exhausted", "SP_Register",
     "/\\ ss[s].life = \"Active\" /\\ ~ss[s].quar /\\ ExhR(ss[s])\n    /\\ d \\in Clients",
     "/\\ ss[s].life = \"Active\" /\\ ~ss[s].quar\n    /\\ d \\in Clients"),
    ("OPERATOR_ADD_KEY clears the revocation markers", "SP_Revoke",
     "    /\\ d \\in Clients \\ ss[s].K /\\ Room(s, 1)\n    /\\ Step(s, 1, [K |-> ss[s].K \\cup {d}])",
     "    /\\ d \\in Clients \\ ss[s].K /\\ Room(s, 1)\n    /\\ Step(s, 1, [K |-> ss[s].K \\cup {d}, rev |-> {}, hard |-> {}])"),
    # T_total: the cumulative cap
    ("T_total a disconnect during verification resets the cap", "SP_Total",
     "/\\ Step(s, 2, [att |-> \"Det\", rk |-> \"none\",\n                         detLeft |-> TDetach] @@ Rec)",
     "/\\ Step(s, 2, [att |-> \"Det\", rk |-> \"none\",\n                         detLeft |-> TDetach, totLeft |-> TTotal] @@ Rec)"),
    ("T_total a restart resets the cap", "SP_Total",
     "!.C = {}, !.rk = \"none\", !.opd = {},",
     "!.C = {}, !.rk = \"none\", !.opd = {}, !.totLeft = TTotal,"),
    ("T_total the cap counts time attached", "SP_Total",
     "!.totLeft = IF r.att = \"Det\" /\\ @ > 0 THEN @ - 1 ELSE @,",
     "!.totLeft = IF @ > 0 THEN @ - 1 ELSE @,"),
    ("T_total the cap does not end the session", "Timers",
     "d == r.att = \"Det\" /\\ (r.detLeft = 0 \\/ r.totLeft = 0)",
     "d == r.att = \"Det\" /\\ r.detLeft = 0"),
    # forwarding acknowledgement
    ("Ack a call is delivered that was never forwarded", "Ack",
     "/\\ Active(s) /\\ k \\in fwd[s] /\\ k \\in ss[s].drained /\\ k \\notin ss[s].dlv",
     "/\\ Active(s) /\\ k \\in ss[s].drained /\\ k \\notin ss[s].dlv", FWD7),
    ("Ack a delivered call is forwarded again", "SP_Forward",
     "/\\ Active(s) /\\ k \\in ss[s].drained /\\ k \\notin ss[s].dlv\n    /\\ k \\notin ss[s].sent",
     "/\\ Active(s) /\\ k \\in ss[s].drained\n    /\\ k \\notin ss[s].sent", DEEP),
    ("Ack a call is forwarded while an escalation is pending", "SP_Forward",
     "    /\\ ss[s].hum = \"None\"\n    /\\ \\/ ss[s].att = \"Att\"",
     "    /\\ \\/ ss[s].att = \"Att\"", FWD7),
    # G1 variants
    ("G1 forward ignores the allowlist", "SP_Allow",
     "/\\ Need(k) \\in Allow /\\ Room(s, 3)",
     "/\\ Room(s, 3)", FWD),
    ("G1 a held call is drained unanswered", "SP_Drain",
     "/\\ r.ans[k] = \"ok\"",
     "/\\ (r.ans[k] = \"ok\" \\/ k \\in r.held)", Q),
]

VIOLATION = re.compile(
    r"Error: (?:Invariant|Action property|Temporal property) (\w+) (?:is|was) violated")


def violated(stdout: str):
    """(error line, property named in it or None)."""
    err = next((ln for ln in stdout.splitlines() if ln.startswith("Error:")), "")
    m = VIOLATION.search(err)
    return err, (m.group(1) if m else None)


def verdict(stdout: str, label: str = "", timed_out: bool = False, single: bool = False) -> str:
    """"killed", "SURVIVED", "WRONG-PROPERTY" or "ERROR" from TLC's output.

    label: the property that must be the one violated (as written in the
    configuration: an invariant, ``Only_SP_x`` or a liveness property).
    single: the configuration lists that property and no other, so a
    violation that TLC reports without a name is attributed to it."""
    if timed_out:
        return "ERROR"
    err, prop = violated(stdout)
    if prop is not None:
        return "killed" if prop == label else "WRONG-PROPERTY"
    if "violated" in err:
        return "killed" if single else "WRONG-PROPERTY"
    if "No error has been found" in stdout and not err:
        return "SURVIVED"
    return "ERROR"


def self_test() -> None:
    v = verdict
    assert v("Error: Invariant I1 is violated.\n", "I1") == "killed"
    assert v("Error: Invariant I11 is violated by the initial state.\n", "I11") == "killed"
    assert v("Error: Invariant Inv is violated.\n", "I1") == "WRONG-PROPERTY"
    assert v("Error: Invariant I10 is violated.\n", "I1") == "WRONG-PROPERTY"
    assert v("Error: Action property Only_SP_I6 is violated.\n", "Only_SP_I6") == "killed"
    assert v("Error: Action property StepProps is violated.\n", "Only_SP_I6") == "WRONG-PROPERTY"
    assert v("Error: Temporal property L1Res was violated.\n", "L1Res") == "killed"
    assert v("Error: Temporal property L2 was violated.\n", "L1") == "WRONG-PROPERTY"
    assert v("Error: Temporal properties were violated.\n", "L1", single=True) == "killed"
    assert v("Error: Temporal properties were violated.\n", "L1") == "WRONG-PROPERTY"
    assert v("Model checking completed. No error has been found.\n", "I1") == "SURVIVED"
    assert v("Error: parsing failed.\n", "I1") == "ERROR"
    assert v("Semantic error in line 3\n", "I1") == "ERROR"
    assert v("", "I1", timed_out=True) == "ERROR"


def base_config(spec_cfg: str) -> str:
    cfg = spec_cfg.replace("Sessions = {s1, s2}", "Sessions = {s1}")
    cfg = cfg.replace("SYMMETRY SessionSym", "")
    return re.sub(r"MaxEvents = \d+", "MaxEvents = 6", cfg)


def apply_cfg(cfg: str, over: dict) -> str:
    for a, b in over.items():
        assert a in cfg, a
        cfg = cfg.replace(a, b)
    return cfg


def config_name(over: dict) -> str:
    return next(n for n, o in CONFIG_NAMES if o is over)


def properties(spec: str) -> dict:
    """The properties of the spec by kind: the conjuncts of Inv, the rules of
    StepProps and the liveness properties of BridgeContractLive.cfg."""
    inv = re.search(r"^Inv ==(.*?)\n\n", spec, re.M | re.S).group(1)
    sp = re.search(r"^StepProps ==(.*?)\]_vars", spec, re.M | re.S).group(1)
    live_cfg = (HERE / "BridgeContractLive.cfg").read_text()
    return {"inv": re.findall(r"[A-Za-z]\w*", inv),
            "step": re.findall(r"\bSP_\w+(?=\(s\))", sp),
            "live": re.findall(r"^PROPERTY (\w+)", live_cfg, re.M)}


def only(spec: str, cfg: str, label: str, props: dict):
    """The spec and configuration that check the labelled property alone;
    returns (spec text, cfg text, the name TLC will print)."""
    cfg = re.sub(r"^(INVARIANT|PROPERTY) .*\n", "", cfg, flags=re.M)
    if label in props["inv"]:
        return spec, cfg + f"\nINVARIANT {label}\n", label
    if label in props["step"]:
        name = f"Only_{label}"
        add = f"\n\\* added by tlc_mutants.py\n{name} == [][\\A s \\in Sessions : {label}(s)]_vars\n\n"
        end = list(re.finditer(r"^={4,}\s*$", spec, re.M))[-1].start()
        return spec[:end] + add + spec[end:], cfg + f"\nPROPERTY {name}\n", name
    assert label in props["live"], label
    return spec, cfg + f"\nPROPERTY {label}\n", label


def every(spec: str, cfg: str, props: dict, live: bool):
    """Every property of the kind, listed one by one (for DIAGNOSE)."""
    cfg = re.sub(r"^(INVARIANT|PROPERTY) .*\n", "", cfg, flags=re.M)
    if live:
        return spec, cfg + "".join(f"\nPROPERTY {p}" for p in props["live"]) + "\n"
    add = "".join(f"Only_{p} == [][\\A s \\in Sessions : {p}(s)]_vars\n" for p in props["step"])
    end = list(re.finditer(r"^={4,}\s*$", spec, re.M))[-1].start()
    cfg += "".join(f"\nINVARIANT {p}" for p in props["inv"])
    cfg += "".join(f"\nPROPERTY Only_{p}" for p in props["step"]) + "\n"
    return spec[:end] + "\n" + add + "\n" + spec[end:], cfg


def check_patches() -> int:
    """No TLC: the verdict logic, the anchors, the labels and the coverage of
    the properties by mutants."""
    self_test()
    spec = (HERE / "BridgeContract.tla").read_text()
    cfg = base_config((HERE / "BridgeContract.cfg").read_text())
    props = properties(spec)
    bad = 0
    names = [m[0] for m in MUTANTS]
    for n in sorted({n for n in names if names.count(n) > 1}):
        print(f"PATCH-ERROR {n}: name used more than once")
        bad += 1
    labelled = set()
    for name, check, old, new, *over in MUTANTS:
        over = over[0] if over else BASE
        if spec.count(old) != 1:
            print(f"PATCH-ERROR {name}: anchor found {spec.count(old)}x")
            bad += 1
        if old == new:
            print(f"PATCH-ERROR {name}: patch changes nothing")
            bad += 1
        if not any(o is over for _, o in CONFIG_NAMES):
            print(f"PATCH-ERROR {name}: configuration has no name in CONFIG_NAMES")
            bad += 1
        for a in over:
            if a not in cfg:
                print(f"PATCH-ERROR {name}: cfg text {a!r} not found")
                bad += 1
        kind = next((k for k in props if check in props[k]), None)
        if kind is None:
            print(f"PATCH-ERROR {name}: label {check} is not a property of the spec")
            bad += 1
        elif (kind == "live") != (over is LIVE):
            print(f"PATCH-ERROR {name}: label {check} ({kind}) does not fit its configuration")
            bad += 1
        labelled.add(check)
    for p in props["inv"] + props["step"] + props["live"]:
        if p not in labelled and p not in NO_OWN_MUTANT:
            print(f"NO-MUTANT {p}: no mutant is labelled with this property")
            bad += 1
    for p in NO_OWN_MUTANT:
        if p in labelled or p not in props["live"] + props["inv"] + props["step"]:
            print(f"PATCH-ERROR {p}: listed in NO_OWN_MUTANT but has a mutant or is not a property")
            bad += 1
    try:                                    # the generated modules are well-formed text
        for p in props["step"][:1] + props["inv"][:1] + props["live"][:1]:
            only(spec, apply_cfg(cfg, LIVE) if p in props["live"] else cfg, p, props)
        every(spec, cfg, props, False)
    except Exception as e:                  # noqa: BLE001
        print(f"PATCH-ERROR building a single-property run: {e!r}")
        bad += 1
    print(f"{len(MUTANTS) - bad} patches apply, every property has a mutant"
          if not bad else f"{bad} problem(s)")
    return 1 if bad else 0


def run_tlc(dd: Path, spec_text: str, cfg_text: str):
    (dd / "m.cfg").write_text(cfg_text)
    (dd / "BridgeContract.tla").write_text(spec_text)
    try:
        p = subprocess.run(
            [JAVA, "-XX:+UseParallelGC", "-cp", JAR, "tlc2.TLC", "-config", "m.cfg", "-workers",
             WORKERS, "-deadlock", "-metadir", str(dd / "meta"), "BridgeContract.tla"],
            cwd=dd, capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return None, "timeout"
    out = p.stdout
    err = violated(out)[0]
    info = err or (out.strip().splitlines()[-1] if out.strip() else "")
    return out, info


def main() -> int:
    if "--check-patches" in sys.argv:
        return check_patches()
    spec = (HERE / "BridgeContract.tla").read_text()
    cfg = base_config((HERE / "BridgeContract.cfg").read_text())
    props = properties(spec)
    todo = [m for m in MUTANTS if not ONLY or any(o in m[0] for o in ONLY)]
    if "--list" in sys.argv:
        for name, check, _old, _new, *over in todo:
            print(f"[{check}] {name}  ({config_name(over[0] if over else BASE)})")
        return 0
    self_test()
    if not JAR:
        print("set TLA2TOOLS to the path of tla2tools.jar")
        return 2
    print(f"spec     BridgeContract.tla sha256 {hashlib.sha256(spec.encode()).hexdigest()}")
    failed = 0
    with tempfile.TemporaryDirectory(prefix="tlcmut-") as d:
        dd = Path(d)
        # no-change control, once for every configuration a mutant uses: the
        # unmodified spec must pass there with all its properties
        for cname, over in CONFIG_NAMES:
            if not any((m[4] if len(m) > 4 else BASE) is over for m in todo):
                continue
            out, info = run_tlc(dd, spec, apply_cfg(cfg, over))
            stats = re.search(r"(\d+) states generated, (\d+) distinct", out or "")
            if out is None or verdict(out) != "SURVIVED":
                print(f"control  [{cname}] the unmodified spec does not pass ({info}); "
                      "the mutant verdicts in this configuration would be vacuous")
                return 2
            print(f"control  [{cname}] the unmodified spec passes"
                  + (f" ({stats.group(2)} distinct states)" if stats else ""), flush=True)
        for name, check, old, new, *over in todo:
            over = over[0] if over else BASE
            if spec.count(old) != 1:
                print(f"PATCH-ERROR {name}: anchor found {spec.count(old)}x")
                failed += 1
                continue
            mcfg = apply_cfg(cfg, over)
            mspec, ocfg, tlc_name = only(spec.replace(old, new), mcfg, check, props)
            out, info = run_tlc(dd, mspec, ocfg)
            outcome = verdict(out or "", tlc_name, timed_out=out is None, single=True)
            print(f"{outcome:8s} [{check}] {name}  <- {info}", flush=True)
            failed += outcome != "killed"
            if outcome == "SURVIVED" and DIAGNOSE:
                dspec, dcfg = every(spec.replace(old, new), mcfg, props, over is LIVE)
                dout, dinfo = run_tlc(dd, dspec, dcfg)
                print(f"         diagnosis, every property listed: {dinfo}", flush=True)
    print(f"\n{len(todo) - failed}/{len(todo)} mutants killed, each by the property its label names")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
