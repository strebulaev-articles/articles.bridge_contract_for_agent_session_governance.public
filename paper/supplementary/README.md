# Supplementary materials

Companion artefacts to the article proper.

## Files

| File | Description |
|------|-------------|
| `conformance_suite.py` | Reference Python bridge (product state model with a client set, challenge-response resume pinned to the acknowledged prefix, durable log and restart recovery, queue limits, answer binding) and the pytest suite for I1-I15 (T1-T158, including the Hypothesis properties T8-T10). |
| `mutation_check.py` | Mutants, at least one per invariant (I1-I15) and one for the timer bounds; every mutant must make at least one test fail. Exits non-zero otherwise. |
| `vectors/` | Language-neutral JSON test vectors V01-V137 and their schema (`vectors/README.md`). |
| `jcs.py` | RFC 8785 canonical JSON for the value types the contract uses; the one encoding behind every hash and signed message of the Python bridge and `wire.py`. `vectors/bytes_kat.json` pins its output, the event and content hashes and the signed bytes of re-attach and join proofs; the Rust crate reads the same file. |
| `run_vectors.py` | Runs the vectors on the Python bridge; `--emit-tex` / `--check-paper` generate and check the paper's vector table (`../sections/generated_vectors.tex`). |
| `traceability.py` | Generates and checks the traceability matrix (`../sections/generated_traceability.tex`) from the pytest docstrings, the vector `covers` fields, the mutant registries, the TLC mutants log and the TLA+ module; `make traceability` / `make traceability-check`. |
| `measure_faults.py` | Seeded fault-injection (event loss of an acknowledging relay against the bridge) and verification-cost measurements; `--emit-tex` writes `../tables/measurements.tex`, raw data in `measurements.json`. |
| `rust-bridge/` | Standalone Rust crate that passes the same vectors (`cargo test`); see its README for the independence caveats. |
| `formal-spec/` | TLA+ model of the product machine, TLC configurations, mutation script and recorded results. |
| `requirements.txt` | pytest, hypothesis, jsonschema, cryptography, pyyaml; install into a venv. |
| `Supporting-Materials.tex` / `.pdf` | Appendix A (Preliminary Research Report), Appendix B (Competitive Landscape), Appendix C (Conformance Test Suite Specification). |

## Running

```bash
python3 -m venv .venv && . .venv/bin/activate     # from the repository root
pip install -r paper/supplementary/requirements.txt
cd paper/supplementary
python3 -I -m pytest conformance_suite.py -q     # the suite
python3 -I mutation_check.py                      # every invariant has a killed mutant
python3 -I run_vectors.py                         # the JSON vectors
(cd rust-bridge && cargo test)                    # the Rust crate on the same vectors
```

`python3 -I` (isolated mode) ignores `PYTHONPATH` and the per-user site-packages directory, so run these inside the venv; a pytest installed with `pip install --user` is invisible to it. See `REPRODUCE.md` for the full list and for `make validate` (`SKIP_RUST=1` skips the Rust step).

TLC: see `formal-spec/README.md`.
