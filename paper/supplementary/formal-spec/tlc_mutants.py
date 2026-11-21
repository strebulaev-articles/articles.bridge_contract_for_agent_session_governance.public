#!/usr/bin/env python3
"""
Sanity check that TLC's verdict on BridgeContract.tla is not vacuous: each
mutant below breaks one invariant in the spec text; TLC (one session,
MaxEvents = 6) must then report an invariant or property violation.

    TLA2TOOLS=/path/to/tla2tools.jar [JAVA=java] [ONLY='part of a name|...'] python3 -I tlc_mutants.py

A mutant is killed only when TLC reports an invariant or property violation
("violated" in its Error line).  "No error has been found" is a survivor;
anything else (a parse or semantic error, a crash, a timeout) is an ERROR and
never a kill.  Before any mutant, a no-change control (the unmodified spec
under the same single-session configuration) must end with "No error has
been found"; otherwise every verdict below would be vacuous and the script
stops.

    python3 -I tlc_mutants.py --check-patches   # no TLC: every anchor applies
                                                # exactly once and the verdict
                                                # logic is self-tested
"""
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

# (name, expected failing check, old text, new text[, cfg replacements])
Q = {'DetPolicy = "refuse"': 'DetPolicy = "queue"'}
FWD = {'DetPolicy = "refuse"': 'DetPolicy = "forward"'}
FWD7 = {**FWD, "MaxEvents = 6": "MaxEvents = 7"}
# deep and narrow: one client, one call key, one challenge; enough events for
# forward, deliver, restart, re-attach and forward again
DEEP = {**FWD, "MaxEvents = 6": "MaxEvents = 11",
        'Clients = {"c1", "c2"}': 'Clients = {"c1"}',
        'Keys = {"k1", "k2"}': 'Keys = {"k1"}', "MaxNonce = 2": "MaxNonce = 1"}
# the attacker on: the base configuration has it off (the large configurations
# do not need it), the attacker-model mutants switch it on
ATK = {"AttackOn = FALSE": "AttackOn = TRUE", "ObsMax = 0": "ObsMax = 2"}
# three client keys: one to revoke, one to stay, one to register
C3 = {'Clients = {"c1", "c2"}': 'Clients = {"c1", "c2", "c3"}'}
# liveness: fair scheduling with L1, L2 and CapEnds instead of the step
# properties
LIVE = {"SPECIFICATION Spec": "SPECIFICATION FairSpec", "VIEW SafetyView\n": "",
        "PROPERTY StepProps": "PROPERTY L1\nPROPERTY L2\nPROPERTY CapEnds",
        "MaxEvents = 6": "MaxEvents = 5"}
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
    ("I3 widening applied", "I3",
     "/\\ Active(s) /\\ ~(ns \\subseteq ss[s].scope) /\\ Room(s, 1)\n    /\\ Step(s, 1, [life |-> \"Active\"])",
     "/\\ Active(s) /\\ ~(ns \\subseteq ss[s].scope) /\\ Room(s, 1)\n    /\\ Step(s, 1, [scope |-> ns])"),
    ("I7 cell change without an event", "StepProps",
     "Step(s, k, u) ==\n    ss' = [ss EXCEPT ![s] = ([n |-> ss[s].n + k] @@ u) @@ ss[s]]",
     "Step(s, k, u) ==\n    ss' = [ss EXCEPT ![s] = ([n |-> ss[s].n] @@ u) @@ ss[s]]"),
    ("I11 an unauthentic request is accepted", "StepProps",
     "accept == authentic /\\ live /\\ pre = \"ok\" /\\ r.att # \"Res\"",
     "accept == live /\\ pre = \"ok\" /\\ r.att # \"Res\""),
    ("I9 an expired nonce is accepted", "StepProps",
     "live == issued /\\ r.nb[claimed] > 0 /\\ claimed \\notin r.nu",
     "live == issued /\\ claimed \\notin r.nu"),
    ("I9 a nonce outlives T_nonce", "I9",
     "![ss[s].nid + 1] = TNonce]]",
     "![ss[s].nid + 1] = TNonce + 1]]"),
    ("I11 a spent nonce is accepted again", "StepProps",
     "live == issued /\\ r.nb[claimed] > 0 /\\ claimed \\notin r.nu",
     "live == issued /\\ r.nb[claimed] > 0"),
    ("I11 an accepted nonce is not consumed", "StepProps",
     "THEN Step(s, 1, [C |-> r.C \\cup {key}, nu |-> r.nu \\cup {claimed},",
     "THEN Step(s, 1, [C |-> r.C \\cup {key}, nu |-> r.nu,"),
    ("I4 the prefix is not checked", "StepProps",
     "accept == authentic /\\ live /\\ pre = \"ok\" /\\ r.att # \"Res\"",
     "accept == authentic /\\ live /\\ r.att # \"Res\""),
    ("I5 resume verifies a corrupt chain", "StepProps",
     "IF ss[s].corrupt\n       THEN Step(s, 1, [quar |-> TRUE])      \\* RESUME_FAILED: rule Q\n       ELSE Step(s, 1, [att |-> \"Att\", C |-> {ss[s].rk}, rk |-> \"none\"])",
     "Step(s, 1, [att |-> \"Att\", C |-> {ss[s].rk}, rk |-> \"none\"])"),
    ("Rule D: drain while detached", "StepProps",
     "/\\ Active(s) /\\ ss[s].att = \"Att\" /\\ ss[s].hum = \"None\"\n    /\\ ss[s].queue # {}",
     "/\\ Active(s) /\\ ss[s].hum = \"None\"\n    /\\ ss[s].queue # {}"),
    ("I13 drain skips scope revalidation", "StepProps",
     "/\\ Need(k) \\in r.scope}",
     "/\\ TRUE}"),
    ("I13 drain ignores approval expiry", "StepProps",
     "/\\ (r.apprLeft > 0 \\/ k \\in r.held)",
     "/\\ TRUE"),
    ("I14 drain ignores the answer", "StepProps",
     "/\\ r.ans[k] = \"ok\"",
     "/\\ TRUE"),
    ("I12 forward before the DRAINED event", "I2",
     "/\\ Active(s) /\\ k \\in ss[s].drained /\\ k \\notin ss[s].dlv",
     "/\\ Active(s) /\\ k \\in ss[s].queue /\\ k \\notin ss[s].dlv"),
    ("I13 queue bound ignored", "I13",
     "IF Cardinality(r.queue) < QMax\n       THEN Step(s, 1, [queue |-> r.queue \\cup {k},\n                        callLeft",
     "IF TRUE\n       THEN Step(s, 1, [queue |-> r.queue \\cup {k},\n                        callLeft"),
    ("I6 clean end leaves the session active", "StepProps",
     "/\\ Step(s, 1, [life |-> \"Terminated\", endWhy |-> \"clean\"])",
     "/\\ Step(s, 1, [life |-> \"Terminated\", endWhy |-> \"clean\", scope |-> {}])"),
    ("Timers: T_detach not stopped in Res", "Timers",
     "[att |-> \"Res\", rk |-> key, recorded |-> FALSE,\n                                      detLeft |-> NoTimer, nu |->",
     "[att |-> \"Res\", rk |-> key, recorded |-> FALSE,\n                                      nu |->"),
    ("I15 a partial departure detaches", "I15",
     "/\\ Step(s, 1, [C |-> ss[s].C \\ {c}])",
     "/\\ Step(s, 2, [att |-> \"Det\", C |-> ss[s].C \\ {c}, detLeft |-> TDetach] @@ Rec)"),
    ("I15 an unregistered key is authentic", "I15",
     "known == key \\in r.K /\\ Verifies(key, sig, claimed, pre)",
     "known == Verifies(key, sig, claimed, pre)"),
    ("I15 a key is registered without a connected client", "StepProps",
     "/\\ Active(s) /\\ ss[s].att = \"Att\" /\\ c \\in ss[s].C \\ ss[s].rev /\\ d \\notin ss[s].K",
     "/\\ Active(s) /\\ d \\notin ss[s].K"),
    ("I15 a completed resume attaches nobody", "I15",
     "ELSE Step(s, 1, [att |-> \"Att\", C |-> {ss[s].rk}, rk |-> \"none\"])",
     "ELSE Step(s, 1, [att |-> \"Att\", C |-> {}, rk |-> \"none\"])"),
    ("I15 a restart keeps the client set", "I15",
     "!.C = {}, !.rk = \"none\", !.opd = {},\n                                  !.sent = {}, !.uf = 0,",
     "!.rk = \"none\", !.opd = {},\n                                  !.sent = {}, !.uf = 0,"),
    # attacker model (C.1): possession, forgery, replay
    ("Attacker holds a client's signing key", "StepProps",
     "AdvSigs(claimed, pre) == [by : AdvKeys,",
     "AdvSigs(claimed, pre) == [by : AdvKeys \\cup Clients,", ATK),
    ("Attacker: a signature verifies under any key", "StepProps",
     "sig.by = key /\\ sig.nonce = claimed /\\ sig.pre = pre",
     "sig.nonce = claimed /\\ sig.pre = pre", ATK),
    ("Attacker: a signature is not bound to its nonce", "StepProps",
     "sig.by = key /\\ sig.nonce = claimed /\\ sig.pre = pre",
     "sig.by = key /\\ sig.pre = pre", ATK),
    ("Attacker: a signature is not bound to the prefix verdict", "StepProps",
     "sig.by = key /\\ sig.nonce = claimed /\\ sig.pre = pre",
     "sig.by = key /\\ sig.nonce = claimed", ATK),
    # I11 (f), (g): bounded nonce book, bounded unauthenticated log
    ("I11f a challenge ignores the live-nonce limit", "Inv",
     "    /\\ Cardinality(LiveSet(ss[s])) < LiveLimit     \\* full book: refused (I11f)\n",
     ""),
    ("I11f a challenge evicts a live nonce", "StepProps",
     "    /\\ Cardinality(LiveSet(ss[s])) < LiveLimit     \\* full book: refused (I11f)\n    /\\ ss' = [ss EXCEPT ![s].nid = @ + 1,",
     "    /\\ ss' = [ss EXCEPT ![s].nid = @ + 1, ![s].nu = @ \\cup LiveSet(ss[s]),"),
    ("I11g unauthenticated failures are all recorded", "StepProps",
     "recorded == known \\/ r.uf < FailMax",
     "recorded == TRUE"),
    ("I11g a request that verifies is dropped past the limit", "StepProps",
     "recorded == known \\/ r.uf < FailMax",
     "recorded == r.uf < FailMax"),
    ("I11g an authentic request does not restore the allowance", "StepProps",
     "ufn == IF known THEN 0 ELSE r.uf + 1",
     "ufn == IF known THEN r.uf ELSE r.uf + 1"),
    # rule Q: quarantine
    ("Q a chain failure terminates the session", "Inv",
     "THEN Step(s, 1, [quar |-> TRUE])      \\* RESUME_FAILED: rule Q",
     "THEN Step(s, 2, [life |-> \"Terminated\"])"),
    ("Q a recovery failure terminates the session", "Inv",
     "THEN [r EXCEPT !.quar = TRUE, !.n = @ + 1]   \\* RECOVERY_FAILED",
     "THEN [r EXCEPT !.life = \"Terminated\", !.n = @ + 2]"),
    ("Q a quarantined session keeps ticking", "StepProps",
     "IF r.life = \"Terminated\" \\/ r.quar THEN r\n    ELSE [r EXCEPT",
     "IF r.life = \"Terminated\" THEN r\n    ELSE [r EXCEPT"),
    ("Q a restart touches a quarantined session", "StepProps",
     "IN IF r.life = \"Terminated\" \\/ r.quar THEN r",
     "IN IF r.life = \"Terminated\" THEN r"),
    # I11-REVOKE: key lifecycle
    ("I11-REVOKE a revoked key is accepted", "StepProps",
     "authentic == known /\\ key \\notin r.rev",
     "authentic == known"),
    ("I11-REVOKE revoking a key removes it from K", "TypeOK",
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
     "ELSE IF r.att = \"Res\" /\\ r.rk = c\n",
     "ELSE IF FALSE\n"),
    ("I11-REVOKE a revoked client registers a key", "StepProps",
     "c \\in ss[s].C \\ ss[s].rev /\\ d \\notin ss[s].K",
     "c \\in ss[s].C /\\ d \\notin ss[s].K", C3),
    ("key_exhausted does not freeze the session", "StepProps",
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
    ("OPERATOR_ADD_KEY on a session that is not key_exhausted", "StepProps",
     "/\\ ss[s].life = \"Active\" /\\ ~ss[s].quar /\\ ExhR(ss[s])\n    /\\ d \\in Clients",
     "/\\ ss[s].life = \"Active\" /\\ ~ss[s].quar\n    /\\ d \\in Clients"),
    ("OPERATOR_ADD_KEY clears the revocation markers", "StepProps",
     "OperatorAddKey(s, d) ==\n    /\\ ss[s].life = \"Active\" /\\ ~ss[s].quar /\\ ExhR(ss[s])\n    /\\ d \\in Clients \\ ss[s].K /\\ Room(s, 1)\n    /\\ Step(s, 1, [K |-> ss[s].K \\cup {d}])",
     "OperatorAddKey(s, d) ==\n    /\\ ss[s].life = \"Active\" /\\ ~ss[s].quar /\\ ExhR(ss[s])\n    /\\ d \\in Clients \\ ss[s].K /\\ Room(s, 1)\n    /\\ Step(s, 1, [K |-> ss[s].K \\cup {d}, rev |-> {}, hard |-> {}])"),
    # T_total: the cumulative cap
    ("T_total a disconnect during verification resets the cap", "StepProps",
     "/\\ Step(s, 2, [att |-> \"Det\", rk |-> \"none\",\n                         detLeft |-> TDetach] @@ Rec)",
     "/\\ Step(s, 2, [att |-> \"Det\", rk |-> \"none\",\n                         detLeft |-> TDetach, totLeft |-> TTotal] @@ Rec)"),
    ("T_total a restart resets the cap", "StepProps",
     "!.C = {}, !.rk = \"none\", !.opd = {},",
     "!.C = {}, !.rk = \"none\", !.opd = {}, !.totLeft = TTotal,"),
    ("T_total the cap counts time attached", "StepProps",
     "!.totLeft = IF r.att = \"Det\" /\\ @ > 0 THEN @ - 1 ELSE @,",
     "!.totLeft = IF @ > 0 THEN @ - 1 ELSE @,"),
    # forwarding acknowledgement
    ("Ack a delivered call is forwarded again", "StepProps",
     "/\\ Active(s) /\\ k \\in ss[s].drained /\\ k \\notin ss[s].dlv\n    /\\ k \\notin ss[s].sent",
     "/\\ Active(s) /\\ k \\in ss[s].drained\n    /\\ k \\notin ss[s].sent", DEEP),
    ("Ack a call is forwarded while an escalation is pending", "StepProps",
     "    /\\ ss[s].hum = \"None\"\n    /\\ \\/ ss[s].att = \"Att\"",
     "    /\\ \\/ ss[s].att = \"Att\"", FWD7),
    # G1 variants
    ("G1 forward ignores the allowlist", "StepProps",
     "/\\ Need(k) \\in Allow /\\ Room(s, 3)",
     "/\\ Room(s, 3)", FWD),
    ("G1 a held call is drained unanswered", "StepProps",
     "/\\ r.ans[k] = \"ok\"",
     "/\\ (r.ans[k] = \"ok\" \\/ k \\in r.held)", Q),
]


def verdict(stdout: str, timed_out: bool = False) -> str:
    """"killed", "SURVIVED" or "ERROR" from TLC's output."""
    if timed_out:
        return "ERROR"
    err = next((ln for ln in stdout.splitlines() if ln.startswith("Error:")), "")
    if "violated" in err:
        return "killed"
    if "No error has been found" in stdout and not err:
        return "SURVIVED"
    return "ERROR"


def self_test() -> None:
    assert verdict("Error: Invariant I1 is violated.\n") == "killed"
    assert verdict("Model checking completed. No error has been found.\n") == "SURVIVED"
    assert verdict("Error: parsing failed.\n") == "ERROR"
    assert verdict("Semantic error in line 3\n") == "ERROR"
    assert verdict("", timed_out=True) == "ERROR"


def base_config(spec_cfg: str) -> str:
    cfg = spec_cfg.replace("Sessions = {s1, s2}", "Sessions = {s1}")
    cfg = cfg.replace("SYMMETRY SessionSym", "")
    return re.sub(r"MaxEvents = \d+", "MaxEvents = 6", cfg)


def check_patches() -> int:
    """No TLC: the verdict logic, and every anchor applies exactly once."""
    self_test()
    spec = (HERE / "BridgeContract.tla").read_text()
    cfg = base_config((HERE / "BridgeContract.cfg").read_text())
    bad = 0
    for name, _check, old, new, *over in MUTANTS:
        if spec.count(old) != 1:
            print(f"PATCH-ERROR {name}: anchor found {spec.count(old)}x")
            bad += 1
        if old == new:
            print(f"PATCH-ERROR {name}: patch changes nothing")
            bad += 1
        for a in (over[0] if over else {}):
            if a not in cfg:
                print(f"PATCH-ERROR {name}: cfg text {a!r} not found")
                bad += 1
    print(f"{len(MUTANTS) - bad} patches apply" if not bad else f"{bad} problem(s)")
    return 1 if bad else 0


def run_tlc(dd: Path, spec_text: str, cfg_text: str) -> tuple[str, str]:
    (dd / "m.cfg").write_text(cfg_text)
    (dd / "BridgeContract.tla").write_text(spec_text)
    try:
        p = subprocess.run(
            [JAVA, "-cp", JAR, "tlc2.TLC", "-config", "m.cfg", "-workers",
             os.environ.get("WORKERS", "2"), "-deadlock", "-metadir", str(dd / "meta"),
             "BridgeContract.tla"],
            cwd=dd, capture_output=True, text=True, timeout=900)
    except subprocess.TimeoutExpired:
        return verdict("", timed_out=True), "timeout"
    err = next((ln for ln in p.stdout.splitlines() if ln.startswith("Error:")), "")
    return verdict(p.stdout), err or p.stdout.strip().splitlines()[-1:][0] if p.stdout.strip() else ""


def main() -> int:
    if "--check-patches" in sys.argv:
        return check_patches()
    self_test()
    if not JAR:
        print("set TLA2TOOLS to the path of tla2tools.jar")
        return 2
    spec = (HERE / "BridgeContract.tla").read_text()
    cfg = base_config((HERE / "BridgeContract.cfg").read_text())
    survived = 0
    with tempfile.TemporaryDirectory(prefix="tlcmut-") as d:
        dd = Path(d)
        # no-change control: the unmodified spec must pass in this configuration
        outcome, info = run_tlc(dd, spec, cfg)
        if outcome != "SURVIVED":
            print(f"control: the unmodified spec gave {outcome} ({info}); "
                  "the mutant verdicts would be vacuous")
            return 2
        print("control  the unmodified spec passes")
        for name, check, old, new, *over in MUTANTS:
            if ONLY and not any(o in name for o in ONLY):
                continue
            mcfg = cfg
            for a, b in (over[0] if over else {}).items():
                assert a in cfg
                mcfg = mcfg.replace(a, b)
            if spec.count(old) != 1:
                print(f"PATCH-ERROR {name}: anchor found {spec.count(old)}x")
                survived += 1
                continue
            outcome, err = run_tlc(dd, spec.replace(old, new), mcfg)
            print(f"{outcome:8s} [{check}] {name}  <- {err}")
            survived += outcome != "killed"
    print(f"\n{len(MUTANTS) - survived}/{len(MUTANTS)} mutants killed")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
