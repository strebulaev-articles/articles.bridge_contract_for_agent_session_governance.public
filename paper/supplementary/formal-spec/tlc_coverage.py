#!/usr/bin/env python3
"""
Which cells and which actions does each TLC configuration reach?

    TLA2TOOLS=/path/tla2tools.jar JAVA=java python3 -I tlc_coverage.py [CONFIG ...]

For each configuration (default: all) it finds the cells of the product machine
that the configuration reaches, one probe invariant at a time (a violation of
``Probe_X`` in BridgeContractCover.tla means cell X is reached), then runs the
configuration to completion with the probes of the unreached cells and
``-coverage 1`` to count, per action, the distinct states it generated. Output
is JSON on stdout. The genesis cell (Att, None) is reached by Init.

Every action that ``Next`` names must appear under its own name in TLC's
coverage report; a report that still files states under ``Next`` (an action
TLC could not name, as it did for the two forms of ``Present`` while their
quantifiers ran over a state-dependent set) stops the script. The two forms
are reported as ``PresentHonest`` and ``PresentAdv``, and their sum as
``Present``.

    python3 -I tlc_coverage.py --check   # no TLC: the action names of Next and
                                         # the parser of the coverage report
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
JAR = os.environ.get("TLA2TOOLS")
JAVA = os.environ.get("JAVA", "java")
# Limits for a shared host. TLC_WORKERS: TLC worker threads ("auto" uses every core).
# TLC_JAVA_OPTS: JVM options, e.g. "-Xmx6g -XX:ParallelGCThreads=1".
WORKERS = os.environ.get("TLC_WORKERS", "auto")
JAVA_OPTS = os.environ.get("TLC_JAVA_OPTS", "-XX:+UseParallelGC").split()
CELLS = ["AttNone", "AttPend", "DetNone", "DetPend", "ResNone", "ResPend",
         "Terminated", "Quarantined", "KeyExhausted"]
DEFAULT = ["BridgeContract", "BridgeContractDeep", "BridgeContractLive",
           "BridgeContractQueue", "BridgeContractForward", "BridgeContractLongHuman",
           "BridgeContractAttack", "BridgeContractBook"]
# operators that Next applies and that are not actions
NOT_ACTIONS = {"KeyIds"}
PRESENT = ("PresentHonest", "PresentAdv")


def next_actions() -> list[str]:
    """The actions Next names, from the text of the module."""
    spec = (HERE / "BridgeContract.tla").read_text()
    spec = re.sub(r"\(\*.*?\*\)", "", spec, flags=re.S)
    spec = re.sub(r"\\\*.*", "", spec)
    defs = set(re.findall(r"(?m)^([A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*==", spec))
    body = re.search(r"(?ms)^Next ==(.*?)^Spec ==", spec).group(1)
    seen = []
    for w in re.findall(r"[A-Za-z_]\w*", body):
        if w in defs and w not in NOT_ACTIONS and w not in seen:
            seen.append(w)
    return seen


def parse_coverage(out: str, expected: list[str]) -> dict[str, int]:
    """Distinct states per action from the last statistics block of a
    ``-coverage`` run; every expected action must be there by name."""
    block = out[out.rindex("<Init line"):]
    actions: dict[str, int] = {}
    for m in re.finditer(r"<(\w+) line [^>]*>: (\d+):\d+", block):
        actions[m.group(1)] = actions.get(m.group(1), 0) + int(m.group(2))
    actions.pop("Init", None)
    if "Next" in actions:
        raise SystemExit("tlc_coverage: TLC filed states under Next; an action has no name of its own")
    missing = [a for a in expected if a not in actions]
    if missing:
        raise SystemExit(f"tlc_coverage: no coverage line for {', '.join(missing)}")
    actions["Present"] = sum(actions[p] for p in PRESENT)
    return actions


def self_check() -> int:
    expected = next_actions()
    assert all(p in expected for p in PRESENT), expected
    assert "Next" not in expected and "Tick" in expected and "Challenge" in expected, expected
    line = "<{} line 1, col 1 to line 2, col 2 of module BridgeContract>: {}:{}\n"
    out = "junk\n" + line.format("Init", 1, 1) + "".join(line.format(a, i, 2 * i) for i, a in enumerate(expected))
    got = parse_coverage(out, expected)
    assert got["Present"] == got["PresentHonest"] + got["PresentAdv"]
    for bad in (out + line.format("Next", 5, 5), out.replace("<Tick line", "<Other line")):
        try:
            parse_coverage(bad, expected)
        except SystemExit:
            continue
        raise AssertionError("an unnamed or missing action was accepted")
    print("tlc_coverage: " + ", ".join(expected))
    return 0


def cfg_for(name: str, probes: list[str], dst: Path) -> None:
    text = (HERE / f"{name}.cfg").read_text()
    text = re.sub(r"^SPECIFICATION .*$", "SPECIFICATION Spec", text, flags=re.M)
    text = re.sub(r"^(INVARIANT|PROPERTY) .*\n", "", text, flags=re.M)
    text += "".join(f"\nINVARIANT Probe_{p}" for p in probes) + "\n"
    dst.write_text(text)


def latest_checkpoint(meta: Path):
    """The newest directory under meta that holds a TLC checkpoint, or None."""
    files = sorted(meta.rglob("*.chkpt"), key=lambda f: f.stat().st_mtime) if meta.is_dir() else []
    return files[-1].parent if files else None


def tlc(name: str, probes: list[str], meta: Path, checkpoint: bool):
    """One TLC run with coverage. With checkpoint, TLC writes a checkpoint every
    TLC_CHECKPOINT_MIN minutes into meta and the run continues from the newest one
    if meta already holds one. Returns (output, recovered)."""
    cfg = meta.parent / "run.cfg"
    meta.parent.mkdir(parents=True, exist_ok=True)
    cfg_for(name, probes, cfg)
    rec = latest_checkpoint(meta) if checkpoint else None
    cmd = [JAVA, *JAVA_OPTS, "-cp", JAR, "tlc2.TLC", "-config", str(cfg),
           "-workers", WORKERS, "-deadlock", "-metadir", str(meta), "-coverage", "1",
           *(["-checkpoint", os.environ.get("TLC_CHECKPOINT_MIN", "15")] if checkpoint else []),
           *(["-recover", str(rec)] if rec else []), "BridgeContractCover.tla"]
    return subprocess.run(cmd, cwd=HERE, capture_output=True, text=True).stdout, rec is not None


def one(name: str, expected: list[str]) -> dict:
    """Probe rounds, each a full run with coverage that stops at the first probe
    that fires; the run in which none fires is the coverage run. With TLC_STATE set
    the finished runs are kept (a restart reuses them) and a run in progress is
    checkpointed. TLC does not restore its counters on recovery (tested on
    BridgeContractQueue: the distinct-state total and most action counts differ from an
    uninterrupted run). A result that includes a recovered run therefore has
    resumed=true and never_conclusive=false: its cells are exact, its counts are
    not, and an action it lists as never firing may have fired before the
    checkpoint. Rerun that configuration without interruption to settle it."""
    root = os.environ.get("TLC_STATE")
    state = Path(root) / name if root else Path(tempfile.mkdtemp())
    state.mkdir(parents=True, exist_ok=True)
    found, resumed = {"AttNone"}, False
    while True:
        probes = [c for c in CELLS if c not in found]
        key = hashlib.sha1(",".join(probes).encode()).hexdigest()[:8]
        saved = state / f"run-{key}.out"
        if root and saved.exists():
            out = saved.read_text()
        else:
            out, rec = tlc(name, probes, state / f"meta-{key}", bool(root))
            resumed |= rec
            if root:
                saved.write_text(out)
                shutil.rmtree(state / f"meta-{key}", ignore_errors=True)
        hit = re.search(r"Invariant Probe_(\w+) is violated", out)
        if not hit:
            break
        found.add(hit.group(1))
    actions = parse_coverage(out, expected)
    stats = re.search(r"(\d+) states generated, (\d+) distinct", out)
    return {"config": name, "cells": sorted(found), "unreached": [c for c in CELLS if c not in found],
            "distinct": int(stats.group(2)),
            "actions": actions, "resumed": resumed, "never_conclusive": not resumed,
            "never": sorted(a for a, n in actions.items() if n == 0)}


if __name__ == "__main__":
    if "--check" in sys.argv:
        sys.exit(self_check())
    if not JAR:
        sys.exit("set TLA2TOOLS to the path of tla2tools.jar")
    names = next_actions()
    for n in sys.argv[1:] or DEFAULT:
        print(json.dumps(one(n, names)), flush=True)
