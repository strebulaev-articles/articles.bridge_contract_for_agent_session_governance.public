#!/usr/bin/env python3
"""
Traceability matrix: each invariant to its TLA+ property, tests, vectors and
mutants, generated from the files that hold those facts.

    python3 -I traceability.py --emit-tex ../sections/generated_traceability.tex
    python3 -I traceability.py --check-paper ../sections/generated_traceability.tex
    python3 -I traceability.py --show          # plain text, for review

Sources (nothing is typed into the table by hand except the limits below):

* tests       the first paragraph of each pytest docstring in
              conformance_suite.py (tags such as ``I11(c)``, ``I1-I3``, and
              ``[trace: I12 rule Q]`` where the prose names no invariant);
* vectors     the ``covers`` list of each vectors/V*.json;
* mutants     the registries in mutation_check.py (Python bridge),
              mutation_check_rust.py (Rust crate) and formal-spec/tlc_mutants.py
              (TLA+ module), the last with the verdicts in the newest TLC log
              directory (``mutants.log``);
* TLA+        the state invariants listed in ``Inv``, the labelled conjuncts of
              ``StepProps`` and the liveness properties in BridgeContract.tla,
              and the configurations that check them.

A cell with no entry must have a stated limit in LIMITS, and a limit must
not be stated for a cell that has entries; either mismatch fails the check,
so a limit cannot go stale silently.  Entries that name a test, vector or
mutant that does not exist fail too.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
VECTORS = sorted((HERE / "vectors").glob("V*.json"))

# Row id -> label.  Order is the order in the table.
ROWS = [
    ("I1", "I1"), ("I2", "I2"), ("I3", "I3"), ("I4", "I4"), ("I5", "I5"),
    ("I6", "I6"), ("I7", "I7"), ("I8", "I8"), ("I9", "I9"), ("I10", "I10"),
    ("I11", "I11 (a)--(e)"), ("I11f", "I11 (f)"), ("I11g", "I11 (g)"),
    ("I12", "I12"), ("I13", "I13"), ("I14", "I14"), ("I15", "I15"),
    ("I11-REVOKE", "I11-REVOKE"), ("I-OPERATOR", "I-OPERATOR"),
    ("I-GRANT", "I-GRANT"), ("I-CHECKPOINT", "I-CHECKPOINT"),
    ("I-SIGN-EVENT", "I-SIGN-EVENT"), ("I-SIGN-JWKS", "I-SIGN-JWKS"),
    ("TIMERS", "Timer bounds"), ("L1", "L1"), ("L2", "L2"),
    ("Q", "Rule Q"), ("D", "Rule D"), ("WIRE", "Wire format"),
]
ROW_IDS = [r for r, _ in ROWS]

# Limits: why an empty cell is empty.  Keyed by (row, column); columns are
# model, tests, vectors, py, rust, tla.  Short on purpose: the reasons are
# argued where the claim is made (Sections on the conformance suite and the
# formal model), and the cross-references in the paper point there.
LIMITS: dict[tuple[str, str], str] = {
    ("I2", "tla"): "the model's mutant for this check is filed under I12",
    ("L2", "rust"): "liveness is checked by TLC only",
    ("I8", "model"): "transport flag; not modelled",
    ("I-GRANT", "model"): "attach and grants not modelled",
    ("I-CHECKPOINT", "model"): "not modelled",
    ("I-CHECKPOINT", "rust"): "the crate has no CHECKPOINT emission",
    ("I-SIGN-EVENT", "model"): "keys and services outside the bridge",
    ("I-SIGN-EVENT", "tests"): "outside the reference bridge; no test",
    ("I-SIGN-EVENT", "vectors"): "outside the reference bridge; no vector",
    ("I-SIGN-EVENT", "py"): "no mutant",
    ("I-SIGN-JWKS", "model"): "keys and services outside the bridge",
    ("I-SIGN-JWKS", "tests"): "inspection of key sources; no test",
    ("I-SIGN-JWKS", "vectors"): "no vector",
    ("I-SIGN-JWKS", "py"): "no mutant",
    ("WIRE", "model"): "bytes are outside the model",
}
# Default for a Rust cell with no entry and no limit above: the Rust mutants
# are a sample of the highest-value rules (mutation_check_rust.py).  A TLA+
# mutant cell is "not modelled" when the row has no TLA+ property.
DEFAULT_LIMIT = {"rust": "not among the sampled rules"}

# Known-answer files that are not scenario vectors.
KAT_FILES = {"WIRE": ["bytes_kat.json", "p256_kat.json"]}

# Step-property conjuncts that also carry a row the spec's heading does not
# name (the conjunct's text does: the drain needs the matching answer; the
# frozen key_exhausted session is left only by the operator).  The check
# fails when the heading no longer exists.
TLA_HEAD_EXTRA = {"Rule D, I13": ["I14"], "key_exhausted": ["I-OPERATOR"]}

# Mutant-name rules: Python registry labels that name an invariant only
# loosely, and the TLA+ mutant prefixes.
PY_LABEL = {"IOPERATOR": "I-OPERATOR", "IGRANT": "I-GRANT",
            "ICHECK": "I-CHECKPOINT", "CANON": "WIRE", "WIRE": "WIRE"}
PY_NAME_ROW = [("L1-", "L1"), ("L2-", "L2"), ("RuleD-", "D"), ("challenge-evicts-live-nonce", "I11f"),
               ("unauthenticated-rejections-unbounded", "I11g")]
RUST_LABEL = {"I11c": "I11", "I11d": "I11", "I11b": "I11", "I11e": "I11",
              "I11f": "I11f", "I11g": "I11g"}
TLA_PREFIX = {"Rule": "D", "Timers": "TIMERS", "T_total": "TIMERS", "Q": "Q",
              "Ack": "D", "G1": "D", "key_exhausted": "I11-REVOKE",
              "OPERATOR_ADD_KEY": "I-OPERATOR", "Attacker": "I11"}
# Vector ``covers`` labels that name a row (other labels are plan items).
COVER_ROW = {"I11f": "I11f", "I11g": "I11g", "rule D": "D", "G1": "D",
             "quarantine": "Q", "registry-log": "I11", "registry-scope": "I11",
             "attach-possession": "I-GRANT", "recovery": "I12"}
# TLA+ names: state invariants and step-property headings.
TLA_STATE_ROW = {"Timers": "TIMERS", "IRev": "I11-REVOKE", "Ack": "D",
                 "EndCause": "Q", "IBook": "I11f", "IFail": "I11g"}
TLA_HEAD_ROW = {"Rule D": "D", "rule Q": "Q", "T_total": "TIMERS",
                "key_exhausted": "I11-REVOKE", "I11-REVOKE": "I11-REVOKE"}
TLA_LIVE_ROW = {"L1": "L1", "L2": "L2", "CapEnds": "TIMERS"}


# A test whose docstring does not name the invariant the paper attributes to
# it carries the tag in the first paragraph of its docstring, as
# ``[trace: I12 rule Q]`` (rows by the same spelling as the plain tags; the
# word ``wire`` names the wire-format row).
TRACE_MARK = re.compile(r"\[trace:\s*([^\]]*)\]")


def row_for_inv(num: str, letters: str) -> str:
    if num == "11" and set(letters) & {"f"}:
        return "I11f"
    if num == "11" and set(letters) & {"g"}:
        return "I11g"
    return f"I{num}"


# ---------------------------------------------------------------- tests ----

def parse_tests() -> dict[str, set[str]]:
    """test id (T7, T19c) -> rows its docstring names."""
    text = (HERE / "conformance_suite.py").read_text()
    out: dict[str, set[str]] = {}
    pat = re.compile(r'^def test_(T\d+[a-z]?)_\w+\(.*?\):\n(?:\s+"""(.*?)""")?',
                     re.M | re.S)
    for m in pat.finditer(text):
        doc = (m.group(2) or "").strip().split("\n\n")[0]
        marked: set[str] = set()
        for mark in TRACE_MARK.finditer(doc):
            marked |= tags(mark.group(1))
        out[m.group(1)] = tags(doc) | marked
    return out


def tags(doc: str) -> set[str]:
    rows: set[str] = set()
    doc = re.sub(r"\s+", " ", doc)
    for m in re.finditer(r"I-(OPERATOR|GRANT|CHECKPOINT)", doc):
        rows.add("I-" + m.group(1))
    doc = re.sub(r"I-(OPERATOR|GRANT|CHECKPOINT)", " ", doc)
    for m in re.finditer(r"\bI11-REVOKE", doc):
        rows.add("I11-REVOKE")
    doc = doc.replace("I11-REVOKE", " ")
    for m in re.finditer(r"\bI(\d+)-I(\d+)\b", doc):           # I1-I3
        for n in range(int(m.group(1)), int(m.group(2)) + 1):
            rows.add(f"I{n}")
    doc = re.sub(r"\bI\d+-I\d+\b", " ", doc)
    for m in re.finditer(r"\bI(\d+)(?:\(([a-g,]+)\)|([a-g])\b)?", doc):
        letters = (m.group(2) or m.group(3) or "").replace(",", "")
        if m.group(1) == "11" and letters:
            sub = {row_for_inv("11", c) for c in letters}
            rows |= sub
        else:
            rows.add(row_for_inv(m.group(1), letters))
    # tags written "I7/I12"
    for m in re.finditer(r"/I(\d+)\b", doc):
        rows.add(f"I{m.group(1)}")
    for t in ("L1", "L2"):
        if re.search(rf"\b{t}\b", doc):
            rows.add(t)
    if re.search(r"\brule Q\b", doc):
        rows.add("Q")
    if re.search(r"\brule D\b", doc):
        rows.add("D")
    if re.match(r"wire\b", doc):
        rows.add("WIRE")
    if re.search(r"\bTIMERS\b", doc):
        rows.add("TIMERS")
    # I11 (a-e) letters other than f, g also keep the base row
    if re.search(r"\bI11\((?=[a-g,]*[a-e])", doc) or re.search(r"\bI11[a-e]\b", doc):
        rows.add("I11")
    return {r for r in rows if r in ROW_IDS}


# -------------------------------------------------------------- vectors ----

def parse_vectors() -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    rows: dict[str, set[str]] = {r: set() for r in ROW_IDS}
    requires: dict[str, set[str]] = {}
    for p in VECTORS:
        v = json.loads(p.read_text())
        requires[v["id"]] = set(v.get("requires", []))
        for c in v.get("covers", []):
            r = COVER_ROW.get(c)
            if r is None and c in ROW_IDS:
                r = c
            if r:
                rows[r].add(v["id"])
    return rows, requires


# -------------------------------------------------------------- mutants ----

def parse_py_mutants() -> dict[str, list[str]]:
    text = (HERE / "mutation_check.py").read_text()
    out: dict[str, list[str]] = {r: [] for r in ROW_IDS}
    for m in re.finditer(r'Mutant\(\s*"([^"]+)",\s*"([^"]+)"', text):
        name, lab = m.groups()
        row = PY_LABEL.get(lab, lab)
        for frag, r in PY_NAME_ROW:
            if (name.startswith(frag) if frag.endswith("-") else frag in name):
                row = r
        if row not in out:
            raise SystemExit(f"traceability: Python mutant {name}: unknown row {row}")
        out[row].append(name)
    return out


def parse_rust_mutants() -> dict[str, list[str]]:
    text = (HERE / "mutation_check_rust.py").read_text()
    out: dict[str, list[str]] = {r: [] for r in ROW_IDS}
    for m in re.finditer(r'Mutant\(\s*"([^"]+)",\s*"([^"]+)"', text):
        name, lab = m.groups()
        row = RUST_LABEL.get(lab, lab)
        if row not in out:
            raise SystemExit(f"traceability: Rust mutant {name}: unknown row {row}")
        out[row].append(name)
    return out


def tla_log() -> Path:
    logs = sorted((ROOT / "docs" / "logs").glob("*tlc*/mutants.log"),
                  key=lambda p: p.parent.name)   # tlc-<date> sorts after the older p<N>-tlc
    return logs[-1]




def parse_tla_mutants() -> dict[str, list[str]]:
    text = (HERE / "formal-spec" / "tlc_mutants.py").read_text()
    names = re.findall(r'^    \("([^"]+)",\s*"[^"]+"', text, re.M)
    killed = set(re.findall(r"^killed\s+\[[^\]]+\]\s+(.*?)\s+<-", tla_log().read_text(), re.M))
    out: dict[str, list[str]] = {r: [] for r in ROW_IDS}
    for name in names:
        pre = name.split()[0].rstrip(":")
        row = TLA_PREFIX.get(pre, pre)
        if row not in out:
            raise SystemExit(f"traceability: TLA+ mutant {name!r}: unknown row {row}")
        if name not in killed:
            raise SystemExit(f"traceability: TLA+ mutant {name!r} is not killed in "
                             f"{tla_log().relative_to(ROOT)}")
        out[row].append(name)
    return out


# ----------------------------------------------------------------- TLA+ ----

def parse_tla() -> dict[str, list[str]]:
    spec = (HERE / "formal-spec" / "BridgeContract.tla").read_text()
    out: dict[str, list[str]] = {r: [] for r in ROW_IDS}
    inv = re.search(r"^Inv ==(.*?)\n\n", spec, re.M | re.S).group(1)
    for name in re.findall(r"[A-Za-z]\w*", inv):
        if name == "TypeOK":
            continue
        row = TLA_STATE_ROW.get(name, name)
        if row in out:
            out[row].append(f"Inv.{name}")
        else:
            raise SystemExit(f"traceability: Inv conjunct {name}: unknown row")
    sp = re.search(r"^StepProps ==(.*?)\]_vars", spec, re.M | re.S).group(1)
    seen_extra: set[str] = set()
    for conj in re.split(r"\n      /\\ ", sp):
        m = re.match(r"\\\* (.*?):", conj)
        if not m:
            continue
        head = m.group(1)
        rows = set()
        for tok in re.split(r"[,/]\s*|\s+and\s+", head):
            tok = tok.strip()
            if tok not in ("I11f", "I11g"):
                tok = re.sub(r"^(I\d+)[a-g]$", r"\1", tok)
            tok = TLA_HEAD_ROW.get(tok, tok)
            if tok in out:
                rows.add(tok)
        for r in TLA_HEAD_EXTRA.get(head, []):
            rows.add(r)
            seen_extra.add(head)
        for r in rows:
            out[r].append(f"StepProps[{head}]")
    for h in TLA_HEAD_EXTRA:
        if h not in seen_extra:
            raise SystemExit(f"traceability: spec has no StepProps conjunct headed {h!r}")
    for name in re.findall(r"^(L1|L2|CapEnds) ==", spec, re.M):
        out[TLA_LIVE_ROW[name]].append(name)
    return out


def tla_configs() -> tuple[list[str], list[str]]:
    safe, live = [], []
    for cfg in sorted((HERE / "formal-spec").glob("*.cfg")):
        t = cfg.read_text()
        if re.search(r"^PROPERTY (L1|L2|CapEnds)", t, re.M):
            live.append(cfg.stem)
        if re.search(r"^INVARIANT Inv", t, re.M) and re.search(r"^PROPERTY StepProps", t, re.M):
            safe.append(cfg.stem)
    return safe, live


# ---------------------------------------------------------------- table ----

def tkey(i: str) -> tuple[int, str]:
    m = re.match(r"[TV](\d+)(.*)", i)
    return int(m.group(1)), m.group(2)


def ranges(ids: set[str], universe: list[str]) -> str:
    """Compress ids that are consecutive in ``universe``."""
    order = sorted(universe, key=tkey)
    pos = {i: k for k, i in enumerate(order)}
    for i in ids:
        if i not in pos:
            raise SystemExit(f"traceability: {i} does not exist")
    ks = sorted(pos[i] for i in ids)
    out, k = [], 0
    while k < len(ks):
        j = k
        while j + 1 < len(ks) and ks[j + 1] == ks[j] + 1:
            j += 1
        a, b = order[ks[k]], order[ks[j]]
        out.append(a if j == k else (f"{a}, {b}" if j == k + 1 else f"{a}--{b}"))
        k = j + 1
    return ", ".join(out)


def tt(s: str) -> str:
    s = (s.replace("\\", "\\textbackslash{}").replace("_", "\\_\\allowbreak{}")
          .replace("&", "\\&").replace("#", "\\#").replace("%", "\\%")
          .replace("-", "-\\allowbreak{}").replace(".", ".\\allowbreak{}"))
    return s


def short(name: str, row: str) -> str:
    base = row.replace("I-", "I").replace("-", "")
    for pre in (row + "-", base + "-", row.replace("-", "") + "-"):
        if name.startswith(pre) and len(name) > len(pre):
            return name[len(pre):]
    return name


def build() -> dict:
    tests = parse_tests()
    trows: dict[str, set[str]] = {r: set() for r in ROW_IDS}
    for t, rs in tests.items():
        for r in rs:
            trows[r].add(t)
    vrows, requires = parse_vectors()
    return dict(tests=tests, trows=trows, vrows=vrows, requires=requires,
                py=parse_py_mutants(), rust=parse_rust_mutants(),
                tlam=parse_tla_mutants(), tla=parse_tla(),
                vids=[json.loads(p.read_text())["id"] for p in VECTORS])


def cells(d: dict, row: str) -> dict[str, str]:
    c: dict[str, str] = {}
    c["tla"] = ", ".join(f"\\texttt{{{tt(x)}}}" for x in d["tla"][row])
    c["tests"] = ranges(d["trows"][row], list(d["tests"])) if d["trows"][row] else ""
    c["vectors"] = ranges(d["vrows"][row], d["vids"]) if d["vrows"][row] else ""
    for f in KAT_FILES.get(row, []):
        if not (HERE / "vectors" / f).exists():
            raise SystemExit(f"traceability: {f} does not exist")
        c["vectors"] += (", " if c["vectors"] else "") + f"\\texttt{{{tt(f)}}}"
    for key, col in (("py", "py"), ("rust", "rust"), ("tlam", "tla_m")):
        names = d[key][row]
        c[col] = ", ".join(f"\\texttt{{{tt(short(n, row))}}}" for n in names)
    c["model"] = c["tla"]
    return c


def render() -> tuple[str, list[str]]:
    d = build()
    problems: list[str] = []
    used: set[tuple[str, str]] = set()
    body = []

    def cell(row: str, col: str, val: str, modelled: bool = True) -> str:
        lim = LIMITS.get((row, col))
        if lim:
            used.add((row, col))
        if val and lim:
            problems.append(f"{row}/{col} has entries and a stated limit ({lim!r}); drop it")
        if val:
            return val
        if lim is None and col in DEFAULT_LIMIT:
            lim = DEFAULT_LIMIT[col]
        if lim is None and col == "tla" and not modelled:
            lim = "not modelled"
        if lim is None:
            problems.append(f"{row}/{col} is empty with no stated limit")
            lim = "?"
        return f"--- ({tt(lim)})"

    for row, label in ROWS:
        c = cells(d, row)
        modelled = bool(c["tla"])
        out = {col: cell(row, col, c[key]) for col, key in
               (("model", "tla"), ("tests", "tests"), ("vectors", "vectors"))}
        parts = [f"\\textbf{{{tag}}}: " + cell(row, col, c[key], modelled)
                 for col, key, tag in (("py", "py", "Py"), ("rust", "rust", "Rs"),
                                       ("tla", "tla_m", "TLA+"))]
        body.append(f"{label} & {out['model']} & {out['tests']} & {out['vectors']} & "
                    + "\\newline ".join(parts) + " \\\\")
    for k in LIMITS:
        if k not in used:
            problems.append(f"limit {k} is stated for a cell that does not exist")
    col = ">{\\raggedright\\arraybackslash}"
    head = ("% GENERATED by supplementary/traceability.py --emit-tex; do not edit.\n"
            "\\begingroup\\tiny\\setlength{\\tabcolsep}{2pt}\n"
            f"\\begin{{longtable}}{{@{{}}p{{0.09\\columnwidth}} {col}p{{0.17\\columnwidth}} "
            f"{col}p{{0.14\\columnwidth}} {col}p{{0.12\\columnwidth}} "
            f"{col}p{{0.44\\columnwidth}}@{{}}}}\n"
            "\\caption{Traceability matrix: invariant, TLA+ property, tests, vectors "
            "and mutants.}\\label{tab:traceability}\\\\\n")
    hdr = ("\\toprule\n\\textbf{Row} & \\textbf{TLA+ property} & \\textbf{Tests} & "
           "\\textbf{Vectors} & \\textbf{Mutants killed (Py: Python bridge; "
           "Rs: Rust crate; TLA+: model)} \\\\\n\\midrule\n")
    text = (head + hdr + "\\endfirsthead\n" + hdr + "\\endhead\n"
            + "\n".join(body) + "\n\\bottomrule\n\\end{longtable}\n\\endgroup\n")
    return text, problems


def show() -> None:
    d = build()
    for row, _ in ROWS:
        print(f"== {row}")
        print("  tla  ", d["tla"][row])
        print("  tests", sorted(d["trows"][row], key=tkey))
        print("  vecs ", sorted(d["vrows"][row], key=tkey))
        print("  py   ", d["py"][row])
        print("  rust ", d["rust"][row])
        print("  tlam ", d["tlam"][row])


def main(argv: list[str]) -> int:
    if "--show" in argv:
        show()
        return 0
    text, problems = render()
    for p in problems:
        print(f"traceability: {p}", file=sys.stderr)
    if "--emit-tex" in argv:
        Path(argv[argv.index("--emit-tex") + 1]).write_text(text)
    if "--check-paper" in argv:
        path = Path(argv[argv.index("--check-paper") + 1])
        if not path.exists() or path.read_text() != text:
            print(f"traceability: {path} is stale; run traceability.py --emit-tex {path}",
                  file=sys.stderr)
            return 1
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
