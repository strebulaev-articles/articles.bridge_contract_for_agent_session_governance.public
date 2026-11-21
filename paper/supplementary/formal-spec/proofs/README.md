# Machine-checked inductive invariants of the bridge-contract model

This directory holds mechanised checks of the safety part of the model. They
support a bounded claim only. The paper does not rely on them yet; the
evidence for the model properties remains the TLC runs of `../BridgeContract.tla`
(see `../README.md`), which the checks here complement and do not replace.

## What is machine-checked

Apalache (`BridgeFull.tla`): for a typed single-session version of the whole
TLA+ model, every state invariant of `Inv` and every step property of
`StepProps` is checked to be inductive, over fixed small universes. The base
case (the initial state satisfies the state invariants) and the inductive step
(from any state that satisfies the state invariants, every step of `Next`
leaves them true and satisfies the step properties) are both checked.
Features, as in the model: key lifecycle (client set, revoke, soft and hard,
add key, key exhaustion, operator end), human escalation and its timer,
the tool queue (submit, expire, answer, drain), forwarding and its
acknowledgement, detached-call policies, scope narrowing and rejected
extension, the nonce book, the failure record, the attacker (it signs with
keys it holds and replays observed signatures), log corruption and the
quarantine rule, restart with recovery faults, and the timers.

Bounds. The universes are fixed: client keys c1--c3, attacker keys x and y,
nonce ids 1--3, call keys k1 and k2, permissions p1 and p2. The timers
and limits range over small intervals set in `CInit` (for example `TDetach`
in 1..5, `LiveLimit` in 1..3, `QMax` in 1..2), and the detached-call policy,
the allowlist and the fault switch range over all their values. Apalache
checks all of them symbolically in one run, not one by one. The result does
not extend to larger universes, nor to unbounded keys or nonces.

`BridgeFull.tla` is a hand-maintained text, separate from `../BridgeContract.tla`
(unlike `BridgeContractTP.tla`, which `make-tp-model.sh` derives from the real
model). A change to one must be made to the other by hand and both rerun.

Structural link. `scripts/check-tla-link.py` (run by `make validate` and the
evidence workflow) extracts from both files the constants, state variables,
action names (the operators called from `Next` and `Core`), state-invariant
names (the conjuncts of `Inv` and `StateInv`) and the fields of `InitRec`, and
fails on any difference that is not in the allowlist at the top of the script.
The allowlist holds the intentional differences with a reason each (one
session, dropped `MaxEvents` and `MaxRestarts`, constants fixed in `CInit`,
the forwarded-call set folded into the record, the ghost `prv`, the extra
state invariants `LastInv` and `KeysHonest`); a stale allowlist entry also
fails. Limits: it compares names only. It does not detect a changed guard,
effect, bound or invariant body, nor a step property (the contract states
them inline in `StepProps`, `BridgeFull.tla` as `SP_*`). A differential trace
check (replaying TLC traces of the real model through `BridgeFull.tla` with
Apalache) was not built: it needs the Apalache image and a TLC run, neither
of which is available offline, and it needs a trace-to-state mapping for the
folded record and the single session. So equivalence of behaviour is still
argued by hand and by the matching mutant results, not checked.

Reproduction. `run-apalache.sh` pins the Docker image by digest
(`ghcr.io/apalache-mc/apalache@sha256:9ae9b33e01a36c610f2caabc48c10794ad295b0feedebf60dc9f366e1c573199`,
Apalache 0.63.0; override with `APALACHE_IMAGE`). `apalache-full.sh LOGDIR`
runs the base case, the inductive step and the witnesses, and
`apalache-mutants-full.sh LOGDIR` the mutants; the recorded logs are in
`docs/logs/c2-full/`.

Differences from the TLC model, all in the direction of fewer restrictions
except the first: one session only (the invariants are per session and
sessions interact only through the global clock, so this carries them, but no
multi-session claim is made); the bounds `MaxEvents` and `MaxRestarts` are
dropped (the event count is unbounded); the attacker switch is on. The
record merge `@@` is replaced by record update because Apalache does not
type it.

TLAPS (`BridgeProofI3.tla`, `MergeLemma.tla`): record shape and I3, proved on
the text of the real model (`BridgeContractTP.tla`, derived by
`make-tp-model.sh`; only the record merge operator and `Permutations`
change), for part of the actions. Unchanged since the first spike.

`BridgeSlice.tla` is the earlier single-session slice from that spike, kept
for its recorded logs in `docs/logs/c2-spike/`; `BridgeFull.tla` supersedes it.

The attacker switch is on in every run (`AttackOn = TRUE`); the model
configurations that switch it off are subcases that this check does not run
separately. `Keys` and `Perms` are the full sets {k1, k2} and {p1, p2}; the TLC
configurations that use a smaller set are not rerun here. The ghost record of
the last presentation (`last`) is not fixed at the start of the inductive step;
the record of the previous step (`prv`) equals the current one there, so the
step properties are checked at the state after the step.

## What is not machine-checked

- Liveness (L1, CapEnds, L2): no Apalache route; TLC bounded remains the
  evidence. A TLAPS proof is a large manual effort and has not been started.
- The hash chain: not modelled, so nothing is claimed about it.
- Multi-session behaviour, and any universe larger than the fixed one: the
  result does not extend to unbounded keys or nonces.
- Soundness of the model against the specification text and the
  implementations: the checks are on the TLA+ model only.
- TLAPS: the remaining actions, the assembly of `[Next]`, and all other
  invariants.

## Invariant by method

"Apalache" means inductive for the fixed universes above (base case and
inductive step, `BridgeFull.tla`), with no strengthening beyond the type bounds
in TypeOK: no invariant failed to be inductive and none timed out. "TLC" means
bounded model checking of `../BridgeContract.tla` by the configurations in
`../README.md`; it covers every row and is the only evidence for the last
rows. "TLAPS" is the partial proof in `BridgeProofI3.tla`.

State invariants of `Inv`:

| Invariant | Apalache | TLAPS | TLC bounded |
|---|---|---|---|
| TypeOK | inductive | record shape, part of the actions | yes |
| I1 resume record in Det | inductive | no | yes |
| I2 forward only after drain | inductive | no | yes |
| Ack delivered only if forwarded | inductive | no | yes |
| EndCause | inductive | no | yes |
| I3 scope within the attach scope | inductive | part of the actions | yes |
| I9 nonce lifetime | inductive | no | yes |
| I10 version iff narrowed | inductive | no | yes |
| I13 queue bound and disjointness | inductive | no | yes |
| IBook (I11 f) | inductive | no | yes |
| IFail (I11 g, state part) | inductive | no | yes |
| I15 client set and cell | inductive | no | yes |
| IRev (I11-REVOKE) | inductive | no | yes |
| Timers | inductive | no | yes |
| I6 (trivial state form) | inductive | no | yes |

Step properties of `StepProps` (checked as invariants of the inductive step):

| Property | Apalache | TLAPS | TLC bounded |
|---|---|---|---|
| I6 terminated session never changes | yes | no | yes |
| I3 scope only narrows | yes | no | yes |
| I10 version advances with narrowing | yes | no | yes |
| I7 cell change needs committed events | yes | no | yes |
| I4, I9, I11, I15 entry needs an authentic live nonce, spent by it; NoForgery | yes | no | yes |
| I11 g restore of the allowance (also as state link) | yes | no | yes |
| I11 d spent stays spent | yes | no | yes |
| I11 f challenge keeps live nonces | yes | no | yes |
| I5 resume only on an intact chain (model flag) | yes | no | yes |
| Rule D, I13 what may drain | yes | no | yes |
| I2, I12 what may be forwarded | yes | no | yes |
| Rule Q quarantine changes only by operator end | yes | no | yes |
| T_total cap | yes | no | yes |
| Operator allowlist | yes | no | yes |
| I15 d key registration | yes | no | yes |
| I11-REVOKE monotone, join not revoked | yes | no | yes |
| key_exhausted serves no client operation | yes | no | yes |
| I15 b shrinking client set keeps Att | yes | no | yes |
| Leaving Det only by re-attach, timeout, end | yes | no | yes |

Liveness and the rest:

| Property | Apalache | TLAPS | TLC bounded |
|---|---|---|---|
| L1, CapEnds, L2 | not covered | not covered | yes (fair scheduling) |
| Hash chain I5 as bytes | not modelled | not modelled | not modelled |

I5 appears above only as the model's corruption flag, not as a hash chain.

## Mutants

`apalache-mutants-full.sh` breaks the Apalache model one line at a time; each
mutant must be rejected by the inductive step. All mutants are rejected, none
survives. The mutant of the first spike that survived (nonce not marked spent
on join) is now rejected by the step property on entering Res or joining.
Mutants are a sanity check of the properties, not a proof that every property is
sensitive to every fault: some step properties (for example "forwarded once per
bridge instance") are not in the model's property list and have no mutant.

## Timings

On one host, with several runs sharing it (so upper bounds): base case about 30 s,
inductive step about 90 s, witnesses about 30 s each, each mutant 25 to 100 s.
Logs and per-milestone summaries are in `docs/logs/c2-full/`.

## How to rerun

Docker is required. Apalache (image `ghcr.io/apalache-mc/apalache`):

    ./apalache-full.sh LOGDIR            # base case, inductive step, witnesses
    ./apalache-mutants-full.sh LOGDIR    # mutants, each must be rejected

TLAPS (local image, built once from `Dockerfile.tlapm`):

    docker build -t tlapm-spike -f Dockerfile.tlapm .
    ./make-tp-model.sh
    ./run-tlapm.sh BridgeProofI3.tla
