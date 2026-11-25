# Machine-checked inductive invariants of the bridge-contract model

This directory holds mechanised checks of the safety part of the model. They
support a bounded claim only. The paper does not rely on them yet; the
evidence for the model properties remains the TLC runs of `../BridgeContract.tla`
(see `../README.md`), which the checks here complement and do not replace.

**Status.** `BridgeFull.tla` and `BridgeProofI3.tla` follow the model as it
stands (nonce bound to a key id, `SP_Honest` and `SP_NoReplay`, approval
countdown per call, direct calls, termination effects, a revocation that
abandons a verification whatever its reason). Neither has been run in this
form: the recorded logs (`docs/logs/c2-full/`, `docs/logs/c2-spike/`) are of
the model before these changes. Until the rerun is recorded, the tables below
say what each check covers, not what a run has shown. In particular, whether
the state invariants as written are inductive for the new properties is
argued by hand in the comments of `BridgeFull.tla` and this file, and may
need a strengthening that only the run will show.

## What is machine-checked

Apalache (`BridgeFull.tla`): for a typed single-session version of the whole
TLA+ model, every state invariant of `Inv` and every step property of
`StepProps` is checked to be inductive, over fixed small universes. The base
case (the initial state satisfies the state invariants) and the inductive step
(from any state that satisfies the state invariants, every step of `Next`
leaves them true and satisfies the step properties) are both checked.
Features, as in the model: key lifecycle (client set, revoke, soft and hard,
add key, key exhaustion, operator end), human escalation and its timer,
the tool queue (submit, expire, answer, drain) with an approval countdown per
call, calls with no escalation pending, forwarding and its acknowledgement,
detached-call policies, scope narrowing and rejected extension, the nonce
book with each nonce bound to a key id, the failure record, the attacker (it
signs with keys it holds, replays observed signatures and asks for challenges
under any key id), log corruption and the quarantine rule, restart with
recovery faults, the timers and the effects of termination.

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
names (the conjuncts of `Inv` and `StateInv`), step-property names (the rules
`SP_x` of `StepProps` and `StepInv`) and the fields of `InitRec`, and fails on
any difference that is not in the allowlist at the top of the script. The
allowlist holds the intentional differences with a reason each (one session,
dropped `MaxEvents`, `MaxRestarts` and `GhostOn`, constants fixed in `CInit`,
the forwarded-call set folded into the record, the ghosts `prv` and `pl`, the
extra state invariants `LastInv` and `KeysHonest`, the rule `SP_Fail` that
`BridgeFull.tla` states as `LastInv`); a stale allowlist entry also fails.
Limits: it compares names only. It does not detect a changed guard, effect,
bound or body of an invariant or rule. A differential trace check (replaying
TLC traces of the real model through `BridgeFull.tla` with Apalache) was not
built: it needs the Apalache image and a TLC run, neither of which is
available offline, and it needs a trace-to-state mapping for the folded record
and the single session. So equivalence of behaviour is still argued by hand
and by the matching mutant results, not checked.

Reproduction. `run-apalache.sh` pins the Docker image by digest
(`ghcr.io/apalache-mc/apalache@sha256:9ae9b33e01a36c610f2caabc48c10794ad295b0feedebf60dc9f366e1c573199`,
Apalache 0.63.0; override with `APALACHE_IMAGE`). `apalache-full.sh LOGDIR`
runs the base case, the inductive step and the witnesses, and
`apalache-mutants-full.sh LOGDIR` the mutants (`DRY=1` checks without Docker
that every mutant's edit applies to the module).

Differences from the TLC model, all in the direction of fewer restrictions
except the first two: one session only (the invariants are per session and
sessions interact only through the global clock, so this carries them, but no
multi-session claim is made); the two conjuncts that use `ENABLED` are left
out, because Apalache has none (in `I11`, a challenge is enabled for one key
id iff for every other; in `Timers`, the timeout is due when a timer has run
out); the bounds `MaxEvents` and `MaxRestarts` are dropped (the event count is
unbounded); the attacker switch is on and the ghost is always written. The
record merge `@@` is replaced by record update because Apalache does not type
it.

Why the new properties should be inductive. `SP_Honest` and `SP_NoReplay`
are not inductive on their own: from an arbitrary state the attacker could
hold the signature of a request whose nonce is still live and good for its
key. The state invariant `I11` rules that state out: a nonce is marked good
only for a registered key, and while a good nonce is live no request naming it
under its key was refused (`nr`) or seen (`obs`), because such a request
authenticates and so spends the nonce in the step that processes it. `I11`
also says that what was refused or seen names an issued nonce, which is what
keeps it true when a challenge issues the next id. `IRev` (no revoked key is
being verified) is kept by `Revoke`, which abandons the verification of the
key it revokes.

TLAPS (`BridgeProofI3.tla`, `MergeLemma.tla`): record shape and I3 (the scope
stays within `Perms`), proved on the text of the real model
(`BridgeContractTP.tla`, derived by `make-tp-model.sh`; only the record merge
operator and `Permutations` change), for part of the actions. The field list
and the lemmas for `Resolve`, `TickRec` and `Present` repeat the text of the
model and were edited with it; the proof has not been rerun on the edited
text.

`BridgeSlice.tla` is the earlier single-session slice from that spike, kept
for its recorded logs in `docs/logs/c2-spike/`; `BridgeFull.tla` supersedes it.

The attacker switch is on in every run (`AttackOn = TRUE`); the model
configurations that switch it off are subcases that this check does not run
separately. `Keys` and `Perms` are the full sets {k1, k2} and {p1, p2}; the TLC
configurations that use a smaller set are not rerun here. The ghost record of
the last request answered (`last`) is not fixed at the start of the inductive
step; the record of the previous step (`prv`) equals the current one there and
the previous ghost (`pl`) equals `last`, so the step properties are checked at
the state after the step.

Witnesses (`apalache-full.sh`), each of which must be violated: `Witness` at
length 0 (a resuming session with a pending escalation exists); at length 1,
`WitnessAdv` (the attacker replays an observed signature that authenticates,
and the request is refused and recorded), `WitnessFail` (a request of the
attacker that does not authenticate is counted), `WitnessAccept` (an honest
request is accepted) and `WitnessDirect` (a call outside the scope is
refused). `WitnessAdv` does not ask that the replay be accepted: that it never
is, is `SP_Honest`.

## What is not machine-checked

- Liveness (L1, L1Res, CapEnds, L2): no Apalache route; TLC bounded remains
  the evidence. A TLAPS proof is a large manual effort and has not been
  started.
- The two `ENABLED` conjuncts of the TLC model (above).
- The hash chain: not modelled, so nothing is claimed about it.
- Multi-session behaviour, and any universe larger than the fixed one: the
  result does not extend to unbounded keys or nonces.
- Soundness of the model against the specification text and the
  implementations: the checks are on the TLA+ model only.
- TLAPS: the remaining actions, the assembly of `[Next]`, and all other
  invariants.

## Invariant by method

"Apalache" names the check that covers the row once rerun (base case and
inductive step, `BridgeFull.tla`, fixed universes above). "TLC" means bounded
model checking of `../BridgeContract.tla` by the configurations in
`../README.md`; it covers every row and is the only evidence for the last
rows. "TLAPS" is the partial proof in `BridgeProofI3.tla`.

State invariants of `Inv`:

| Invariant | Apalache | TLAPS | TLC bounded |
|---|---|---|---|
| TypeOK (with the scope within the attach scope) | in `StateInv` | record shape and scope bound, part of the actions | yes |
| I1 resume record in Det | in `StateInv` | no | yes |
| I2 forward only after drain | in `StateInv` | no | yes |
| Ack delivered only if forwarded | in `StateInv` | no | yes |
| EndCause | in `StateInv` | no | yes |
| I9 nonce lifetime | in `StateInv` | no | yes |
| I10 version iff narrowed | in `StateInv` | no | yes |
| I13 queue bound and disjointness | in `StateInv` | no | yes |
| IBook (I11 f) | in `StateInv` | no | yes |
| IFail (I11 g, the bound) | in `StateInv` | no | yes |
| I11 nonce bound to a key id | in `StateInv`, without the `ENABLED` conjunct | no | yes |
| I15 client set and cell | in `StateInv` | no | yes |
| IRev (I11-REVOKE) | in `StateInv` | no | yes |
| Timers | in `StateInv`, without the `ENABLED` conjunct | no | yes |
| I6 no queue and no timer after termination | in `StateInv` | no | yes |

Step properties of `StepProps` (checked as invariants of the inductive step):

| Property | Apalache | TLAPS | TLC bounded |
|---|---|---|---|
| `SP_I6` terminated session never changes | in `StepInv` | no | yes |
| `SP_Scope` scope only narrows | in `StepInv` | no | yes |
| `SP_Version` version advances with narrowing | in `StepInv` | no | yes |
| `SP_I7` cell change needs committed events | in `StepInv` | no | yes |
| `SP_Enter` entry needs an authentic live nonce issued for the key, spent by it | in `StepInv` | no | yes |
| `SP_Honest` an accepted request was presented by an honest client | in `StepInv` | no | yes |
| `SP_NoReplay` a refused request is never accepted later | in `StepInv` | no | yes |
| `SP_Fail` restore of the allowance | as the state invariant `LastInv` | no | yes |
| `SP_Spent` spent stays spent | in `StepInv` | no | yes |
| `SP_Issue` challenge keeps live nonces, issues a live one | in `StepInv` | no | yes |
| `SP_Chain` resume only on an intact chain (model flag) | in `StepInv` | no | yes |
| `SP_Drain` what may drain | in `StepInv` | no | yes |
| `SP_Appr` an approval only runs down | in `StepInv` | no | yes |
| `SP_Direct` direct calls only within the scope, refusals recorded | in `StepInv` | no | yes |
| `SP_Forward` what may be forwarded | in `StepInv` | no | yes |
| `SP_Quarantine` quarantine changes only by operator end | in `StepInv` | no | yes |
| `SP_Total`, `SP_Timeout` cap and timeouts | in `StepInv` | no | yes |
| `SP_Allow` operator allowlist | in `StepInv` | no | yes |
| `SP_Register` key registration | in `StepInv` | no | yes |
| `SP_Revoke`, `SP_Join` monotone, join not revoked | in `StepInv` | no | yes |
| `SP_Exhausted` key_exhausted serves no client operation | in `StepInv` | no | yes |
| `SP_Shrink` shrinking client set keeps Att | in `StepInv` | no | yes |
| `SP_LeaveDet` leaving Det only by re-attach, timeout, end | in `StepInv` | no | yes |

Liveness and the rest:

| Property | Apalache | TLAPS | TLC bounded |
|---|---|---|---|
| L1, L1Res, CapEnds, L2 | not covered | not covered | yes (fair scheduling) |
| Hash chain I5 as bytes | not modelled | not modelled | not modelled |

I5 appears above only as the model's corruption flag, not as a hash chain.

## Mutants

`apalache-mutants-full.sh` breaks the Apalache model one line at a time; each
mutant must be rejected by the inductive step. The script reports a mutant
that is not rejected, and one whose edit did not apply. Mutants are a sanity
check of the properties, not a proof that every property is sensitive to
every fault: some step properties (for example "forwarded once per bridge
instance") are not in the model's property list and have no mutant. Unlike
`../tlc_mutants.py`, the script does not say which property rejected a
mutant: the inductive step checks `Inv` as one formula.

## Timings

Of the recorded runs, on one host with several runs sharing it (so upper
bounds): base case about 30 s, inductive step about 90 s, witnesses about 30 s
each, each mutant 25 to 100 s. The record is wider now (the binding and the
refusals of each nonce, an approval countdown per call), so expect more.

## How to rerun

Docker is required. Apalache (image `ghcr.io/apalache-mc/apalache`):

    ./apalache-full.sh LOGDIR            # base case, inductive step, witnesses
    ./apalache-mutants-full.sh LOGDIR    # mutants, each must be rejected

Expected: `base` and `step` report no error; every witness reports a
violation; every mutant line reports an error outcome.

TLAPS (local image, built once from `Dockerfile.tlapm`):

    docker build -t tlapm-spike -f Dockerfile.tlapm .
    ./make-tp-model.sh
    ./run-tlapm.sh BridgeProofI3.tla
