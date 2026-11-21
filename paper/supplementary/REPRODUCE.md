# Reproducing the reported results

## Environment

Create a virtual environment from `requirements.txt` and run every command
below inside it (from the repository root):

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -r paper/supplementary/requirements.txt
```

`requirements.txt` lists pytest, hypothesis, jsonschema, cryptography and
pyyaml (the last is read by `scripts/article` and so by `make validate`).
`.venv/` is local and untracked; create it anywhere you like.

The commands use `python3 -I` (isolated mode) so that the working directory
and environment variables such as `PYTHONPATH` cannot shadow the standard
library or the suite's own modules. Isolated mode also hides the per-user
site-packages directory (`pip install --user`), so a pytest installed there
is not found (`No module named pytest`). Packages installed into the
activated venv stay visible. Without a venv, drop `-I`.

`make validate` additionally needs `cargo`. It fails, naming the Rust step,
when cargo is missing; `make validate SKIP_RUST=1` skips that step on
purpose. Its last step regenerates the local, gitignored section and code
indexes under `paper/build` and then checks them.

All commands below are run from `paper/supplementary` (the directory that
contains `conformance_suite.py`, `mutation_check.py`, `run_vectors.py`
and the `rust-bridge/` crate) unless they say the repository root.

## Python suite

```sh
python3 -I -m pytest conformance_suite.py -q     # all tests passed
python3 -I mutation_check.py                     # every mutant killed
python3 -I mutation_check.py --strict-attribution  # as CI runs it: fail on any unattributed kill
python3 -I mutation_check_rust.py                # every Rust mutant killed (needs cargo)
python3 -I run_vectors.py                        # all vectors passed
python3 -I run_vectors.py --wire                 # the same, through the wire server
python3 -I run_vectors.py --check-paper ../sections/generated_vectors.tex
python3 -I tests_table.py --check-paper ../sections/generated_tests.tex
python3 -I check_schemas.py
```

From the repository root, `python3 scripts/lint-counts.py` checks every test
and vector range in the prose against the files on disk, and
`python3 scripts/check-tla-link.py` checks the structural link between the two
TLA+ models; `make validate` runs both with the other paper checks.

The `--check-paper` invocation verifies that the vectors table in the
paper matches the vectors on disk. Use a double dash (`--check-paper`);
a single dash (`-check-paper`) is a different argument and will not be
recognised.

## Fault-injection and cost measurements

```sh
python3 -I measure_faults.py                     # print both experiments
python3 -I measure_faults.py --check-paper ../tables/measurements.tex
make measurements                                # from the repository root
```

Seeded; every reported number is a count, so a rerun reproduces the
tables exactly (measured at about seven minutes). `make measurements` rewrites
`paper/tables/measurements.tex` and `measurements.json`. The Rust crate
is not measured because it does not emit `CHECKPOINT`.

## Rust crate

```sh
(cd rust-bridge && cargo test)                   # all vectors on two storages and through the wire server
```

The crate runs the same JSON vectors against two storage backends
(an in-memory store and a file-system store) to exercise the storage
trait, and once more through its wire front-end
(`all_vectors_pass_through_the_wire_server`), the counterpart of
`run_vectors.py --wire`.

## TLC

The TLC runs are described in `formal-spec/README.md`. The
configurations are `BridgeContract.cfg`, `BridgeContractDeep.cfg`,
`BridgeContractAttack.cfg`, `BridgeContractLive.cfg`,
`BridgeContractQueue.cfg`, `BridgeContractForward.cfg` and
`BridgeContractLongHuman.cfg`; the probe module and the per-configuration
coverage script are `BridgeContractCover.tla` and `tlc_coverage.py`.

## Apalache and TLAPS (optional; the paper does not rely on them)

```sh
formal-spec/proofs/apalache-full.sh DIR          # base case, inductive step, witnesses (Docker)
formal-spec/proofs/apalache-mutants-full.sh DIR  # mutants of the inductive check
```

Expected: base case and inductive step `NoError`, each witness violated as
required, each listed mutant `ERROR (12)`; the recorded logs are in
`docs/logs/c2-full/`. The Docker image is pinned by digest in
`formal-spec/proofs/run-apalache.sh`. `BridgeFull.tla` is a hand-maintained
text, separate from `BridgeContract.tla`, with no mechanical link between
them. The TLAPS check is `formal-spec/proofs/run-tlapm.sh`. Details and
bounds: `formal-spec/proofs/README.md`.

## Mutation criteria

A Python mutant counts as killed only when pytest exits with code 1 and
reports a failed test; collection, import and syntax errors are errors, not
kills. `mutation_check.py` prints the failing test ids and whether one
carries the mutant's invariant tag, and runs a no-change control first.
`mutation_check_rust.py` accepts a kill only for a `cargo test` that compiled
and failed a test, and runs the same control. `formal-spec/tlc_mutants.py`
counts a TLC invariant or property violation as a kill and runs the
unmodified specification as a control; `python3 -I tlc_mutants.py
--check-patches` checks that every patch applies, without TLC.

## Runtime requirements

The Python suite requires Python ≥ 3.10, `pytest` ≥ 8.0, and
`hypothesis` ≥ 6.0 (see `requirements.txt`, which also lists jsonschema, cryptography and pyyaml). The Rust crate requires a
recent stable Rust toolchain. TLC is the build recorded in `formal-spec/README.md` (`2026.11.06.222357`, OpenJDK 21); the configurations listed there take about three quarters of an hour together on 8 cores.
