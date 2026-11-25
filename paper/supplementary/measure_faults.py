#!/usr/bin/env python3
"""Fault-injection and verification-cost measurements.

Two experiments, both seeded and deterministic in every reported number
(counts of calls, events and SHA-256 computations; no wall-clock values):

  E1  Event loss with and without the bridge under injected faults.
      The same seeded action schedule is run against (a) the reference
      ``Bridge`` of ``conformance_suite.py`` and (b) an acknowledging
      relay: it numbers every accepted call, keeps the calls and their
      acknowledgements in a store that survives a restart, and replays the
      unacknowledged calls on re-attach, but does not authenticate a
      resume (rules in ``AckRelay``).  Both are scored on the calls and
      replay attempts that both accepted, so the denominators are equal.
      Faults: client disconnects, human timeouts, replayed requests
      (requests that had been accepted, and requests that were refused
      before their key was registered), bridge restarts, and all together.

  E2  Verification cost against log length, with and without
      I-CHECKPOINT, in SHA-256 computations: full hash-chain verification,
      verification of the suffix after the latest checkpoint, one
      Merkle inclusion proof (the tree hash of RFC 9162, ``merkle.py``),
      and the writer-side cost of the checkpoints.

Both systems and all faults are synthetic and written by the author of
the bridge; the numbers show that the mechanisms act as designed on
these schedules, not how a production deployment behaves.

Usage (from paper/supplementary):
  python3 -I measure_faults.py                       # print the tables
  python3 -I measure_faults.py --json out.json       # also write raw data
  python3 -I measure_faults.py --emit-tex ../tables/measurements.tex
  python3 -I measure_faults.py --check-paper ../tables/measurements.tex
"""
from __future__ import annotations

import argparse
import json
import math
import random
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import merkle  # noqa: E402
import conformance_suite as cs  # noqa: E402

GE = cs.GovernanceEvent
SEED = 20260101
TRIALS = 200
STEPS = 60
T_HUMAN = 300.0
T_DETACH = 600.0

# ----------------------------------------------------------------------
# E1: schedules
# ----------------------------------------------------------------------

BASE = {"submit": 6, "escalate": 1, "answer": 2, "advance": 2}
SCENARIOS = {
    "no fault": {},
    "disconnects": {"disconnect": 2, "reattach": 3},
    "human timeouts": {"wait_human": 1},
    "replays": {"disconnect": 1, "reattach": 3, "replay": 2, "resubmit": 2},
    # a second device presents a request before its key is registered
    # (``early``), the key is registered (``register``), and the captured
    # request is presented again (``early_replay``)
    "pre-registration replays": {"disconnect": 1, "reattach": 3, "early": 2,
                                 "register": 1, "early_replay": 3},
    "restarts": {"restart": 1, "reattach": 3},
    "all faults": {"disconnect": 2, "reattach": 3, "wait_human": 1,
                   "replay": 2, "resubmit": 2, "restart": 1, "early": 1,
                   "register": 1, "early_replay": 2},
}


def make_schedule(rng: random.Random, extra: dict) -> list[tuple]:
    weights = {**BASE, **extra}
    names = sorted(weights)
    acts: list[tuple] = []
    nkey = 0
    for _ in range(STEPS):
        a = rng.choices(names, [weights[n] for n in names])[0]
        if a == "submit":
            nkey += 1
            acts.append((a, f"c{nkey:03d}"))
        elif a == "resubmit":
            acts.append((a, f"c{rng.randint(1, max(nkey, 1)):03d}"))
        elif a == "advance":
            acts.append((a, rng.randint(1, 30)))
        elif a == "wait_human":
            acts.append((a, rng.randint(301, 420)))
        else:
            acts.append((a,))
    return acts


# ----------------------------------------------------------------------
# E1: the system without the bridge
# ----------------------------------------------------------------------

class AckRelay:
    """A relay with sequence acknowledgement and replay, and no
    authenticated resume.

    Rules (a design assumption, stated so a reader can disagree):
      * every accepted call gets a sequence number and is written to a
        store that survives a restart, with the open prompt and the
        acknowledgements; the runtime acknowledges a call when it is
        forwarded;
      * a call is forwarded at once while a client is attached and no
        approval prompt is open; otherwise it stays unacknowledged;
      * a disconnect or a restart ends the connection but not the prompt
        or the stored calls;
      * on re-attach every unacknowledged call is replayed, unless a
        prompt is open (they wait for its answer);
      * a prompt that is open for T_HUMAN is denied; the calls behind it
        are dropped and the drop is written to the store, so it leaves a
        trace;
      * the session never terminates on a timeout;
      * a re-attach request is accepted without a nonce or a signature,
        so a replayed request is accepted; a resubmitted key is a new
        call with a new sequence number and is forwarded again;
      * it keeps no registry of keys, so a request from a device it has
        never seen is a re-attach request like any other, and so is that
        request presented again.
    """

    def __init__(self) -> None:
        self.attached = True
        self.prompt_at = None
        self.store: list[list] = []        # [seq, key, acked, disposition]
        self.forwarded: list[str] = []
        self.now = 0.0
        self.reattached_once = False
        self.replays: dict[int, bool] = {}
        self.early_seen = False
        self.early_replays: dict[int, bool] = {}

    def _flush(self) -> None:
        if self.attached and self.prompt_at is None:
            for rec in self.store:
                if not rec[2] and rec[3] is None:
                    rec[2] = True
                    self.forwarded.append(rec[1])

    def submit(self, key: str) -> None:
        self.store.append([len(self.store) + 1, key, False, None])
        self._flush()

    def step(self, act: tuple, i: int) -> None:
        a = act[0]
        if a in ("submit", "resubmit"):
            self.submit(act[1])
        elif a == "escalate":
            if self.prompt_at is None:
                self.prompt_at = self.now
        elif a == "answer":
            if self.prompt_at is not None:
                self.prompt_at = None
                self._flush()
        elif a == "disconnect":
            self.attached = False
        elif a == "reattach":
            if not self.attached:
                self.attached = True
                self.reattached_once = True
                self._flush()
        elif a in ("advance", "wait_human"):
            self.now += act[1]
            if self.prompt_at is not None and self.now - self.prompt_at >= T_HUMAN:
                self.prompt_at = None
                for rec in self.store:
                    if not rec[2] and rec[3] is None:
                        rec[3] = "dropped"      # recorded, not forwarded
                self._flush()
        elif a == "restart":
            self.attached = False               # the store survives
        elif a == "replay":
            if self.reattached_once:
                self.replays[i] = True          # accepted: nothing checks it
        elif a == "early":
            self.early_seen = True
            self.step(("reattach",), i)         # accepted like any request
        elif a == "early_replay":
            if self.early_seen:
                self.early_replays[i] = True    # accepted: nothing checks it
                self.step(("reattach",), i)

    def settle(self, i: int) -> None:
        self.step(("reattach",), i)
        self.step(("answer",), i)

    def calls(self) -> dict:
        """Per accepted key: forward count and what became of it."""
        out: dict[str, dict] = {}
        fw = Counter(self.forwarded)
        for _seq, key, _acked, disp in self.store:
            o = out.setdefault(key, {"fate": "ok", "fw": fw.get(key, 0)})
            if o["fw"] == 0 and disp is None:
                o["fate"] = "lost"
        return out


# ----------------------------------------------------------------------
# E1: the system with the bridge
# ----------------------------------------------------------------------

class BridgeRun:
    def __init__(self) -> None:
        cfg = cs.Config(t_detach=T_DETACH, t_human=T_HUMAN, t_call=T_HUMAN,
                        detached_calls="queue")
        self.env = cs.Env(cfg)
        self.accepted: set[str] = set()
        self.forwarded: list[str] = []
        self.old_request = None
        self.replays: dict[int, bool] = {}
        # a second device: its key is registered only by ``register``
        self.late = cs.ClientKey("ck-2")
        self.early = None                 # (op, request) refused before that
        self.early_replays: dict[int, bool] = {}
        self._seen_bridge, self._seen_n = self.env.bridge, 0

    @property
    def b(self):
        return self.env.bridge

    def _collect(self) -> None:
        """Take new forwards from the bridge and acknowledge them, as the
        agent runtime would."""
        b = self.b
        if b is not self._seen_bridge:          # a restart: new bridge object
            self._seen_bridge, self._seen_n = b, 0
        for _sid, key, _tool in b.forwarded[self._seen_n:]:
            self.forwarded.append(key)
        self._seen_n = len(b.forwarded)
        sid = self.env.sid
        for key in list(b._sess[sid].unacked):
            try:
                b.delivered(sid, key)
            except cs.BridgeError:
                pass

    def _terminated(self) -> bool:
        return self.b._sess[self.env.sid].life == cs.Lifecycle.TERMINATED

    def submit(self, key: str) -> None:
        try:
            st = self.b.submit_tool_call(self.env.sid, "tool", key=key)
        except cs.BridgeError:
            return                        # refused: the agent is told
        if st in ("QUEUED", "FORWARDED"):
            self.accepted.add(key)

    def step(self, act: tuple, i: int) -> None:
        a, env, b = act[0], self.env, self.b
        try:
            if a in ("submit", "resubmit"):
                self.submit(act[1])
            elif a == "escalate":
                b.escalate_to_human(env.sid)
            elif a == "answer":
                env.resolve()
            elif a == "disconnect":
                env.disconnect()
            elif a == "reattach":
                if env.cell()[0] == cs.DET:
                    self.old_request = env.request()
                    b.client_reattach(env.sid, self.old_request)
                    env.sync("ck-1")
            elif a in ("advance", "wait_human"):
                env.clock.advance(act[1])
                b.tick(env.sid)
            elif a == "restart":
                env.restart()
            elif a == "replay":
                if self.old_request is not None and not self._terminated():
                    try:
                        b.client_reattach(env.sid, self.old_request)
                        self.replays[i] = True
                    except cs.BridgeError:
                        self.replays[i] = False
            elif a == "early":
                # the device asks for a challenge under its key id and
                # presents a request; its key is not registered, so the
                # request is refused, and whoever saw it keeps its bytes
                if (not self._terminated()
                        and "ck-2" not in b.registered_keys(env.sid)):
                    op = "join" if env.cell()[0] == cs.ATT else "reattach"
                    req = self.late.request(
                        env.sid, b.challenge(env.sid, "ck-2").nonce,
                        *env.tip(), op)
                    try:
                        b.begin_resume(env.sid, req, op=op)
                    except cs.BridgeError:
                        self.early = (op, req)
            elif a == "register":
                if (env.cell()[0] == cs.ATT
                        and "ck-2" not in b.registered_keys(env.sid)):
                    cs.add_client(b, env.sid, env.key, self.late.public())
            elif a == "early_replay":
                if self.early is not None and not self._terminated():
                    op, req = self.early
                    try:
                        b.begin_resume(env.sid, req, op=op)
                        self.early_replays[i] = True
                        if b.cell_of(env.sid).att == cs.RES:
                            b.complete_resume(env.sid)
                    except cs.BridgeError:
                        self.early_replays[i] = False
        except cs.BridgeError:
            pass                         # an illegal action in this cell
        self._collect()

    def settle(self, i: int) -> None:
        env, b = self.env, self.b
        if self._terminated():
            return
        self.step(("reattach",), i)
        self.step(("answer",), i)
        # let every held call reach its time limit, then evaluate timers
        if not self._terminated():
            env.clock.advance(T_HUMAN + 1)
            b.tick(env.sid)
        self._collect()

    def calls(self) -> dict:
        """Per accepted key: forward count and what became of it."""
        log = self.env.storage.logs[self.env.sid]
        kinds: dict[str, set] = {}
        for ev in log:
            k = ev.payload.get("key")
            if k is not None:
                kinds.setdefault(k, set()).add(ev.kind)
        fw = Counter(self.forwarded)
        out = {}
        for k in self.accepted:
            fate = "ok"
            if k not in fw:
                ks = kinds.get(k, set())
                if ks & {GE.TOOL_CALL_REJECTED, GE.TOOL_CALL_EXPIRED}:
                    fate = "ok"            # disposed with a recorded reason
                elif GE.TOOL_CALL_QUEUED in ks:
                    fate = "orphaned"      # traced, never disposed
                else:
                    fate = "lost"
            out[k] = {"fate": fate, "fw": fw.get(k, 0)}
        return out


def run_e1() -> dict:
    """Each row scores the two systems on the same set: the keys both
    accepted and the replay attempts both made (the bridge refuses calls
    after a timeout terminates the session, the relay never terminates)."""
    out = {}
    for name, extra in SCENARIOS.items():
        rng = random.Random(f"{SEED}/{name}")
        tot = {"relay": Counter(), "bridge": Counter()}
        for _ in range(TRIALS):
            sched = make_schedule(rng, extra)
            res = {}
            for label, sysm in (("relay", AckRelay()), ("bridge", BridgeRun())):
                for i, act in enumerate(sched):
                    sysm.step(act, i)
                sysm.settle(len(sched))
                res[label] = (sysm.calls(), sysm.replays, sysm.early_replays)
            keys = set(res["relay"][0]) & set(res["bridge"][0])
            steps = set(res["relay"][1]) & set(res["bridge"][1])
            early = set(res["relay"][2]) & set(res["bridge"][2])
            for label, (calls, replays, early_replays) in res.items():
                c = tot[label]
                c["accepted"] += len(keys)
                for k in keys:
                    c[calls[k]["fate"]] += 1
                    c["dup"] += calls[k]["fw"] > 1
                c["replays_attempted"] += len(steps)
                c["replays_accepted"] += sum(replays[s] for s in steps)
                c["early_replays_attempted"] += len(early)
                c["early_replays_accepted"] += sum(early_replays[s]
                                                   for s in early)
        out[name] = {k: dict(v) for k, v in tot.items()}
    return out


# ----------------------------------------------------------------------
# E2: verification cost
# ----------------------------------------------------------------------

def _drive_log(target: int, checkpoints: bool, cycles: int | None = None):
    """Grow a real log of the reference bridge by repeating the cycle
    escalate, queue, answer, resolve, deliver.  Without ``cycles`` the
    run stops at the first cycle that brings the log to ``target``
    events and the number of cycles is returned; with ``cycles`` it runs
    exactly that many, so a checkpointed and a plain log hold the same
    non-CHECKPOINT events.  With ``checkpoints`` the count trigger of
    I-CHECKPOINT is on at the default interval (N = 1000 events since
    the last checkpoint)."""
    env = cs.Env(cs.Config(t_detach=10**9, t_human=10**9, t_call=10**9,
                           t_total=10**9, detached_calls="queue"))
    if checkpoints:
        env.config.n_checkpoint = cs.Config().n_checkpoint
    b, sid = env.bridge, env.sid
    i = 0
    while (i < cycles) if cycles is not None else len(env.storage.logs[sid]) < target:
        i += 1
        b.escalate_to_human(sid)
        b.submit_tool_call(sid, "tool", key=f"k{i}")
        env.resolve()
        for key in list(b._sess[sid].unacked):
            b.delivered(sid, key)
        env.clock.advance(1)
        b.tick(sid)
    return env.storage.logs[sid], i


def verify_path(hashes: list[bytes], index: int,
                root: bytes) -> tuple[bool, int]:
    """One inclusion proof under the tree hash of merkle.py (RFC 9162):
    whether it verifies, and the SHA-256 computations the verifier makes
    (the leaf hash and one interior hash per sibling on the path)."""
    path = merkle.inclusion_proof(hashes, index)
    ok = merkle.verify_inclusion(hashes[index], index, len(hashes), path,
                                 root)
    return ok, 1 + len(path)


def _count_root_ops(leaves: int) -> int:
    """SHA-256 computations of the tree hash over ``leaves`` event hashes:
    one per leaf and one per interior node, or one for the empty tree."""
    return 2 * leaves - 1 if leaves else 1


def run_e2(sizes=(1000, 4000, 16000, 64000)) -> list[dict]:
    rows = []
    for target in sizes:
        plain, cycles = _drive_log(target, False)
        withcp, _ = _drive_log(target, True, cycles)
        assert [e.kind for e in withcp if e.kind != GE.CHECKPOINT] == \
            [e.kind for e in plain]               # like for like
        n_plain, n_cp = len(plain), len(withcp)
        cps = [i for i, e in enumerate(withcp) if e.kind == GE.CHECKPOINT]
        # suffix cost of a verifier that runs after every prefix length p:
        # hash the events from the latest checkpoint at or before p to p,
        # plus the one event before the checkpoint to link to it.
        costs = []
        last = None
        cp_set = set(cps)
        for p in range(1, n_cp + 1):
            if (p - 1) in cp_set:
                last = p - 1
            costs.append(p if last is None else (p - last) + (1 if last else 0))
        tail = costs[-1]
        # writer-side: checkpoint k covers tree_size events: event hashes
        # (tree_size) plus the internal nodes of the tree
        writer = 0
        for c in cps:
            ts = withcp[c].payload["tree_size"]
            writer += ts + _count_root_ops(ts)
        # one inclusion proof for the median event against the final root
        hs = [bytes.fromhex(e.event_hash()) for e in withcp[:cps[-1]]]
        root = merkle.merkle_root(hs)
        assert root.hex() == withcp[cps[-1]].payload["root"]
        ok, ops = verify_path(hs, len(hs) // 2, root)
        assert ok
        rows.append({
            "events_plain": n_plain, "events_cp": n_cp,
            "checkpoints": len(cps),
            "mean_interval": round((cps[-1] - cps[0]) / max(len(cps) - 1, 1))
            if len(cps) > 1 else None,
            "full_chain": n_plain, "full_chain_cp": n_cp,
            "suffix_worst": max(costs), "suffix_mean": round(sum(costs) / len(costs)),
            "suffix_final": tail, "inclusion": ops,
            "writer_ops": writer, "writer_per_event": round(writer / n_cp),
        })
    return rows


# ----------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------

def pct(x: int, n: int) -> str:
    return f"{100.0 * x / n:.1f}" if n else "0.0"


def tex(e1: dict, e2: list) -> str:
    L = []
    L.append("% Generated by supplementary/measure_faults.py --emit-tex; do not edit.")
    L.append("\\begin{table}[ht]\\centering\\small")
    L.append("\\caption{Event loss under injected faults, an acknowledging relay against the bridge "
             f"(seed {SEED}, {TRIALS} schedules of {STEPS} actions per row). "
             "Both systems are scored on the same calls and the same replay attempts. "
             "Accepted: calls both accepted. Lost: no delivery and no "
             "trace. Orphaned: queued and logged but without a recorded disposition "
             "(session terminated by a timeout). Dup: keys forwarded twice. "
             "Replays: re-attach requests that had been accepted, presented "
             "again, accepted / attempted. Early: requests that were refused "
             "before their key was registered, presented again before or "
             "after the registration, accepted / attempted.}"
             "\\label{tab:fault-loss}")
    L.append("\\begin{tabular}{@{}l l r r r r r r@{}}\\toprule")
    L.append("Fault & System & Accepted & Lost (\\%) & Orphaned & Dup & Replays & Early \\\\\\midrule")
    for name, d in e1.items():
        first = True
        for label, key in (("relay", "relay"), ("bridge", "bridge")):
            r = d[key]
            rep = f"{r.get('replays_accepted', 0)}/{r.get('replays_attempted', 0)}"
            early = (f"{r.get('early_replays_accepted', 0)}/"
                     f"{r.get('early_replays_attempted', 0)}")
            L.append(f"{name if first else ''} & {label} & {r['accepted']} & "
                     f"{r.get('lost', 0)} ({pct(r.get('lost', 0), r['accepted'])}) & "
                     f"{r.get('orphaned', 0)} & {r.get('dup', 0)} & {rep} & "
                     f"{early} \\\\")
            first = False
        L.append("\\addlinespace")
    L[-1] = "\\bottomrule"
    L.append("\\end{tabular}\\end{table}")
    L.append("")
    L.append("\\begin{table}[ht]\\centering\\small")
    L.append("\\caption{Verification cost in SHA-256 computations against log length. "
             "Events: events of the plain log; the checkpointed log holds the same events "
             "plus the checkpoints and is the one verified. Full: recompute every event "
             "hash of it (I5). Suffix: recompute only from the "
             "latest checkpoint, worst and mean over all prefixes of the checkpointed "
             "log. Proof: one Merkle inclusion proof for a mid-log event (the leaf "
             "hash and one hash per level of the tree of RFC 9162). Writer: total "
             "cost of emitting the checkpoints (event hashes, leaf hashes and interior "
             "nodes), per event of the log; it grows with the log "
             "because the reference recomputes the whole tree at each checkpoint.}"
             "\\label{tab:verify-cost}")
    L.append("\\begin{tabular}{@{}r r r r r r r@{}}\\toprule")
    L.append("Events & Checkpoints & Full & Suffix worst & Suffix mean & Proof & "
             "Writer per event \\\\\\midrule")
    for r in e2:
        L.append(f"{r['events_plain']} & {r['checkpoints']} & {r['full_chain_cp']} & "
                 f"{r['suffix_worst']} & {r['suffix_mean']} & {r['inclusion']} & "
                 f"{r['writer_per_event']} \\\\")
    L.append("\\bottomrule\\end{tabular}\\end{table}")
    return "\n".join(L) + "\n"


def text(e1: dict, e2: list) -> str:
    L = ["E1 event loss (seed %d, %d schedules x %d actions)" % (SEED, TRIALS, STEPS)]
    for name, d in e1.items():
        for key in ("relay", "bridge"):
            L.append(f"  {name:15s} {key:7s} {d[key]}")
    L.append("E2 verification cost (SHA-256 computations)")
    for r in e2:
        L.append("  " + json.dumps(r))
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--json")
    ap.add_argument("--emit-tex")
    ap.add_argument("--check-paper")
    ap.add_argument("--quick", action="store_true",
                    help="small E2 sizes (for tests); not for the paper")
    a = ap.parse_args()
    e1 = run_e1()
    e2 = run_e2((1000, 4000) if a.quick else (1000, 4000, 16000, 64000))
    print(text(e1, e2))
    if a.json:
        Path(a.json).write_text(json.dumps({"e1": e1, "e2": e2}, indent=1) + "\n")
    if a.emit_tex:
        Path(a.emit_tex).write_text(tex(e1, e2))
    if a.check_paper:
        if Path(a.check_paper).read_text() != tex(e1, e2):
            print("STALE: regenerate with make measurements", file=sys.stderr)
            return 1
        print("paper table is current")
    return 0


if __name__ == "__main__":
    sys.exit(main())
