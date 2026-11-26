<!-- README:META:START -->
# Bridge Contract for Agent Session Governance
## Independent specification draft

**Manuscript type:** Preprint
**Version:** v0.10.5 (2026-11-26)
**Authors:** [Sergei A. Strebulaev](https://orcid.org/0009-0006-2710-8910) (Independent Researcher) †
**License:** CC-BY-4.0
**Code license:** MIT
**Target deposit:** Zenodo (preprint)
**Corresponding author(s):** Sergei A. Strebulaev
**DOI:** 10.5281/zenodo.24409592

## Abstract

Existing agent protocols --- the Agent Transfer Protocol (AGTP), the
Governance Audit Record (GAR) and the Protocol for Agent Communication
Exchange (PACE) --- define transport, audit and resumption semantics
for agent sessions, but, in the versions read, none defines what an intermediate bridge MUST
do when the client is detached and the agent keeps executing, or when
the human in the loop is unavailable. We argue that the reason is
scope rather than oversight; this rests on a reading of those drafts
and would weaken if one of them were extended to own these duties.

This document defines the Bridge Contract BC = (S, E, R, C): a Session
Identity Descriptor, Mandatory Governance Events, a Resume Record that
the bridge keeps for itself, and Conformance Criteria. Re-attach is a
challenge-response in which the client proves possession of a
registered key over a single-use nonce and the last event it saw,
and the bridge accepts only a consistent prefix. The log is
hash-chained, which detects edits and reordering inside it but not
the truncation of its last events without a head held outside the log. The normative model
is a product state machine of attachment, human and lifecycle, with
invariants I1--I15 and derived timers. The contract complements
AGTP, GAR and PACE and does not replace them.

Evidence: the product model is checked with TLC on bounded
configurations; a conformance suite (T1--T158) and a mutation check
in which every MUST invariant except the inspection-only I-SIGN-JWKS has
a killed mutant, on a Python bridge; vectors V01--V137 pass on it
and on a Rust crate. Both implementations have the
same author; no third-party implementation exists. The evidence
shows the consistency of one reading of the text, not independent
confirmation; the limits are stated in the limitations section and
the limitations register.

<!-- README:META:END -->

---

## Repository Structure

```
articles.bridge_contract_for_agent_session_governance/
├── README.md
├── LICENSE                    # CC-BY-4.0 paper license
├── LICENSE-CODE               # MIT code license
├── CITATION.cff               # Citation metadata (regenerated from metadata.yaml)
├── .zenodo.json               # Zenodo deposit metadata (regenerated from metadata.yaml)
├── metadata.yaml              # Single source of truth for metadata
├── .gitignore
├── Makefile                   # Build automation (pdf / docx / validate / metadata / clean / analysis)
├── CHANGES.md                 # Version history (v1 → v2 → ...)
├── .github/
│   └── workflows/
│       ├── build-artifacts.yml    # Builds PDF + DOCX on push to paper/**
│       ├── release.yml           # Builds + publishes on v* tags
│       └── validate-latex.yml    # Lint: \input resolves, \cite keys exist, braces balanced
├── paper/
│   ├── article.tex            # Main LaTeX document
│   ├── refs.bib               # BibTeX bibliography
│   ├── Makefile               # Direct paper/ build
│   ├── .latexmkrc             # latexmk config: outdir=build, reproducible
│   ├── sections/
│   │   ├── 00_abstract.tex
│   │   ├── 01_introduction.tex
│   │   ├── 02_methods.tex          # optional; uncomment \input in article.tex
│   │   ├── 03_results.tex          # optional
│   │   ├── 04_discussion.tex       # optional
│   │   ├── 05_conclusion.tex
│   │   ├── 08_backmatter.tex       # COI / Data / AI-use / Version statements
│   │   └── 09_references.tex
│   ├── figures/               # Tracked; referenced via \includegraphics
│   └── tables/                # Generated tables from make analysis
├── data/
│   ├── raw/observations.csv   # fixture data for empirical analysis
│   └── checksums.sha256       # input checksums for reproducibility
├── analysis/
│   ├── analyze.py             # stdlib-only pipeline: CSV → table + figure
│   ├── pyproject.toml         # optional heavy deps (pandas, matplotlib, numpy)
│   └── uv.lock                # lockfile for optional deps
└── scripts/
    ├── article/               # Vendored core library + JSON-first CLI
    │   ├── cli.py             # python3 -m scripts.article
    │   ├── validate.py        # shared validation logic
    │   └── metadata.py        # shared metadata generation
    ├── generate-metadata.py   # Deprecated shim; delegates to scripts.article
    ├── validate-paper.py      # Deprecated shim; delegates to scripts.article
    └── pre-push               # Hook source; `make hooks` installs it
```

## Build Instructions

### Prerequisites
- **LaTeX distribution** with `pdflatex` and `bibtex` (TeX Live, MiKTeX, or MacTeX) — for PDF
- **Pandoc 3.x** — for DOCX
- **Python 3.10+** — for `make metadata` and `make validate`

### Build the PDF (canonical output)
```bash
make pdf        # runs latexmk: pdflatex → bibtex → pdflatex → pdflatex
```
Output: `paper/article.pdf`

### Build the DOCX (derived artifact)
```bash
make docx
```
Output: `manuscript.docx` (in the repository root). The DOCX is regenerated
by CI on every push that touches `paper/**`; you do not need to commit it.

### Validate locally
```bash
make validate   # runs the same checks as .github/workflows/validate-latex.yml
```
The pre-push hook (installed automatically by the scaffold) runs
`python3 -m scripts.article validate` before each push. It lives in
`scripts/githooks/pre-push` and is enabled through `core.hooksPath`. After
cloning an existing repository, run:

```bash
make hooks      # install/reinstall the pre-push hook; safe to rerun
```

### JSON-first CLI

Every Make target above is also available through the vendored CLI. Use
`--json` for CI, hooks, editors, or an optional MCP adapter:

```bash
python3 -m scripts.article validate --json
python3 -m scripts.article metadata --check --json
python3 -m scripts.article status --json
python3 -m scripts.article build pdf --dry-run --json
```

Exit codes are stable: `0` success, `1` diagnostics/failure, `2` usage error,
and `3` internal error. `scripts/validate-paper.py` and
`scripts/generate-metadata.py` remain as deprecated shims for older
repositories and still accept their historical flags.

### Regenerate derived metadata
After editing `metadata.yaml` (e.g. to bump the version or add a DOI):
```bash
make metadata
```
This updates `CITATION.cff`, `.zenodo.json`, the title/author/date block in
`paper/article.tex`, and the citation block below.

### Clean
```bash
make clean      # removes LaTeX build artifacts + manuscript.docx + manuscript.pdf
```

## Citation

<!-- BIBTEX:CITATION:START -->
<!-- Regenerated by `python scripts/generate-metadata.py` from metadata.yaml.
     Edit metadata.yaml, not this block. -->
```bibtex
@misc{ bridge_contract_for_agent_session_governance_v0_10_5,
  author       = { Sergei A. Strebulaev },
  title        = { Bridge Contract for Agent Session Governance },
  year         = { 2026 },
  note         = { v0.10.5 },
  howpublished = { Zenodo },
  doi          = { 10.5281/zenodo.24409592 },
  url          = { https://doi.org/10.5281/zenodo.24409592 },
  license      = { CC-BY-4.0 }
}
```
<!-- BIBTEX:CITATION:END -->

## License

- Manuscript: [CC-BY-4.0](LICENSE)
- Code: [MIT](LICENSE-CODE)

## Conflicts of Interest

See `paper/sections/08_backmatter.tex` for the full COI, Data Availability,
Use of AI Assistance, and Version statements.
