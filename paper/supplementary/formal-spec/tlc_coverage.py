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
"""
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
JAR = os.environ["TLA2TOOLS"]
JAVA = os.environ.get("JAVA", "java")
CELLS = ["AttNone", "AttPend", "DetNone", "DetPend", "ResNone", "ResPend",
         "Terminated", "Quarantined", "KeyExhausted"]
DEFAULT = ["BridgeContract", "BridgeContractDeep", "BridgeContractLive",
           "BridgeContractQueue", "BridgeContractForward", "BridgeContractLongHuman",
           "BridgeContractAttack"]


def cfg_for(name: str, probes: list[str], dst: Path) -> None:
    text = (HERE / f"{name}.cfg").read_text()
    text = re.sub(r"^SPECIFICATION .*$", "SPECIFICATION Spec", text, flags=re.M)
    text = re.sub(r"^(INVARIANT|PROPERTY) .*\n", "", text, flags=re.M)
    text += "".join(f"\nINVARIANT Probe_{p}" for p in probes) + "\n"
    dst.write_text(text)


def tlc(name: str, probes: list[str], work: Path, coverage: bool):
    cfg = work / "run.cfg"
    cfg_for(name, probes, cfg)
    cmd = [JAVA, "-XX:+UseParallelGC", "-cp", JAR, "tlc2.TLC", "-config", str(cfg),
           "-workers", "auto", "-deadlock", "-metadir", str(work / "meta"),
           *(["-coverage", "1"] if coverage else []), "BridgeContractCover.tla"]
    return subprocess.run(cmd, cwd=HERE, capture_output=True, text=True).stdout


def one(name: str) -> dict:
    found, work = {"AttNone"}, Path(tempfile.mkdtemp())
    while True:
        out = tlc(name, [c for c in CELLS if c not in found], work, coverage=False)
        hit = re.search(r"Invariant Probe_(\w+) is violated", out)
        if not hit:
            break
        found.add(hit.group(1))
    out = tlc(name, [c for c in CELLS if c not in found], work, coverage=True)
    assert "Invariant Probe_" not in out, "a probe fired in the final run"
    last = out.rindex("<Init line")           # the final statistics block
    actions = {m.group(1): int(m.group(2)) for m in
               re.finditer(r"<(\w+) line [^>]*>: (\d+):\d+", out[last:])}
    stats = re.search(r"(\d+) states generated, (\d+) distinct", out)
    return {"config": name, "cells": sorted(found), "unreached": [c for c in CELLS if c not in found],
            "distinct": int(stats.group(2)),
            "actions": {a: n for a, n in actions.items() if a != "Init"},
            "never": sorted(a for a, n in actions.items() if n == 0)}


if __name__ == "__main__":
    for n in sys.argv[1:] or DEFAULT:
        print(json.dumps(one(n)), flush=True)
