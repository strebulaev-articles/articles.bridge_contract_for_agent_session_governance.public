# Bridge Contract — TLA+ model

`BridgeContract.tla` models the product machine of the paper (Section 5.1):
attachment `{Att, Det, Res}` x human `{None, Pend}` x lifecycle
`{Active, Terminated}`, plus quarantine on a chain failure, the cumulative
detachment cap `T_total`, the detached-call policy, calls with no escalation
pending, the forwarding acknowledgement and the effects of termination, with
narrow-only authority (I3, I10), a possession predicate on the resume signature
against an explicit attacker and a nonce bound to a key id at issue (I11), a
bounded nonce book and a bounded record of unauthenticated failures
(I11 (f), (g)), token TTL (I9), durable append and restart recovery (I12), and
the tool queue with idempotency keys, call expiry and an approval countdown
per call (I13). Time is a set of countdowns decremented by `Tick`.

| File | Purpose |
|---|---|
| `BridgeContract.tla` | The model, its invariants (`Inv`), step properties (`StepProps`, one operator `SP_x` per rule) and liveness (`L1`, `L1Res`, `L2`, `CapEnds`). |
| `BridgeContract.cfg` | Safety, 2 sessions x 2 principals x 2 permissions, `MaxEvents = 2`, symmetry on sessions. |
| `BridgeContractDeep.cfg` | Safety, 1 session, `MaxEvents = 7`. |
| `BridgeContractAttack.cfg` | Safety with the attacker on (`AttackOn`), 1 session, one permission and one call key, no log tampering, `MaxEvents = 5`, `ObsMax = 2`. |
| `BridgeContractBook.cfg` | Safety with `LiveLimit = 2`, `MaxNonce = 3` and `FailMax = 2`, 1 session, one permission and one call key, no log tampering, `MaxEvents = 5`. |
| `BridgeContractLive.cfg` | `L1`, `L1Res`, `L2`, `CapEnds` under fair scheduling (`FairSpec`), 1 session, `MaxEvents = 5`, the ghost off. |
| `BridgeContractQueue.cfg`, `BridgeContractForward.cfg` | Safety under the `queue` and `forward` detached-call policies. |
| `BridgeContractLongHuman.cfg` | Safety with `THuman > TDetach`. |
| `BridgeContractCover.tla`, `tlc_coverage.py` | Which cells and actions each configuration reaches (probe invariants and `-coverage`); see "What each configuration reaches". |
| `tlc_mutants.py` | Breaks the spec one rule at a time and checks that TLC reports a violation of the property the mutant is labelled with. |

## Running TLC

```bash
curl -L -o tla2tools.jar https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar
java -cp tla2tools.jar tla2sany.SANY BridgeContract.tla                       # parse
for c in BridgeContract BridgeContractDeep BridgeContractAttack BridgeContractBook \
         BridgeContractLive BridgeContractQueue BridgeContractForward BridgeContractLongHuman; do
  java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -config $c.cfg -workers auto -deadlock BridgeContract.tla
done
TLA2TOOLS=$PWD/tla2tools.jar python3 -I tlc_mutants.py                        # mutants, with attribution
TLA2TOOLS=$PWD/tla2tools.jar python3 -I tlc_coverage.py                       # cells and actions reached
python3 -I tlc_mutants.py --check-patches; python3 -I tlc_coverage.py --check # no TLC needed
```

`-deadlock` turns deadlock checking off: bounded actions legitimately stop.

## Attacker model and the nonce bound to a key (I11)

A signature is a record `[by, nonce, pre]`: the key that signed, the nonce and
the prefix verdict it covers. `Verifies(key, sig, claimed, pre)` holds iff
`sig.by = key`, `sig.nonce = claimed` and `sig.pre = pre`; this predicate is
the unforgeability assumption UF (only the holder of a key produces a
signature that verifies for it), stated in one place and not model-checked.
An honest client (`PresentHonest`) signs with a key in `Clients` and its
signature goes on the wire (`obs`, per session). The attacker (`PresentAdv`)
observes the log and the wire, so it can resubmit any signature in `obs`,
builds its own with the keys in `AdvKeys` (the constant, disjoint from
`Clients`), names any registered or unregistered key, any nonce number and any
prefix verdict, asks for challenges under any key id, and so replays and
reorders; it never holds a key of `Clients`.

A challenge names a key id (`Challenge(s, kid)`). The nonce book notes, for
each nonce, the key id it was issued for (`nk`) and whether that key was
registered and not revoked at that moment (`ng`). The guard of `Challenge`
does not read the key id, and the nonce has the same lifetime whatever the
key id: the answer is the same for a registered key, an unregistered one and
one that no session will ever register. A request authenticates (`known`) iff
its key is registered, its signature verifies and the nonce it names was
issued for that key with the mark `ng`. So a nonce issued for a key that was
not registered at that moment never authenticates a request, whatever the
registry becomes (`AddClient` and `OperatorAddKey` leave the book as it is),
and a nonce issued for one key authenticates no other. A request that does not
authenticate is a failure before authentication: it leaves the nonce alone and
is recorded only within the allowance of (g). A request that authenticates
spends its nonce, also when it is refused (revoked key, stale nonce, prefix
mismatch, another request being verified).

What is checked:

* `SP_Enter`: entering `Res`, or growing the client set, needs an authentic
  request with a live, unspent nonce and an acknowledged prefix; the nonce is
  spent by it and was issued for the key that enters, with the mark `ng`.
* `SP_Honest`: every accepted re-attach or join was presented by an honest
  client. The attacker's presentations, replays of observed signatures
  included, are never accepted. It says something only where the attacker
  acts (`BridgeContractAttack.cfg` and the attacker mutants).
* `SP_NoReplay`: a request that was presented and refused is never accepted
  later, whoever presents it again and whatever the registry has become. The
  ghost `nr` notes, per nonce, the client keys of the refused requests that
  carry a matching signature and the verdict "ok" (the others can never be
  accepted: `Verifies` and the verdict do not change, and a key of the
  attacker is never registered). This one does not need the attacker and is
  checked in every safety configuration.
* `I11` (state): a nonce has the mark `ng` only for a registered key; while
  such a nonce is live, no request naming it under its key was refused or seen
  on the wire; what was refused or seen names an issued nonce; and a
  challenge is enabled for one key id iff it is enabled for every other
  (`ENABLED Challenge(s, a) => ENABLED Challenge(s, b)`), the model's form of
  "the answer to a challenge does not depend on the key id".

Mutants: the attacker holds a client key; a signature verifies under any key,
or is not bound to its nonce; a nonce issued for an unregistered key is marked
good, or verifies once the key is registered (killed once by `SP_NoReplay`
with no attacker and once by `SP_Honest` with it); a nonce is accepted for
another key; `CLIENT_ADDED` or `OPERATOR_ADD_KEY` revives the nonces issued
for the new key; a challenge is refused for an unregistered key, or issues a
dead nonce for it; a request refused during a verification keeps its nonce.

Model switches keep the state space small (see "Tuning the state space").
`AttackOn = FALSE` removes the attacker's moves and the wire record; the
configurations that do not concern the attacker run so, and
`BridgeContractAttack.cfg` runs with it on. `ObsMax` bounds how many of the
honest signatures the attacker remembers: an honest request may or may not be
kept (a nondeterministic choice), so the attacker may keep any `ObsMax` of the
signatures it saw, and replays one of them at a time. The bound loses attacks
that combine more than `ObsMax` different remembered signatures.

Not in the attacker: stealing a client key (A7; I11-REVOKE), another session
(the wire format binds the session id; `obs` is per session), the chain (I5),
the transport (I8), operator signatures and the attach proof. A request the
attacker took off the wire before the bridge saw it is not modelled either:
`obs` holds only signatures of requests the bridge processed, so the model
says nothing about a request that is delayed or delivered by someone else.
For the same reason no attack in the model turns on the prefix verdict being
signed (the attacker cannot alter a request in flight, and a processed request
that authenticates has spent its nonce), so that binding has no mutant; it
rests on the tests and vectors. Replaying an observed request that
authenticates is recorded each time (the text of (g) records every failure of
an authentic request), so the log grows with the attacker's replays; (g)
bounds only failures before authentication.

## Nonce book and unauthenticated failures (I11 (f), (g))

The nonce book is the per-session set of issued nonces: `nb` (a countdown per
nonce id), `nk` and `ng` (the binding above), `nu` (spent ids), `nid`
(issued). A nonce is live iff issued, unexpired and unspent. `LiveLimit`
bounds the live nonces; `Challenge` is disabled when the book is full (the
bridge refuses the challenge) and never invalidates a live nonce: `IBook` is
the bound, and `SP_Issue` is the no-eviction rule together with "the nonce
issued is live for `T_nonce`". With `LiveLimit = 1` a challenge is issued only
when no nonce is live, so the no-eviction rule reads over an empty set there;
`BridgeContractBook.cfg` has `LiveLimit = 2` and `MaxNonce = 3`, where a
challenge is issued while another nonce is live and a further one meets a full
book, and the mutant "a challenge evicts a live nonce" keeps the limit and
runs with these values. `FailMax` bounds the failures before authentication
that are recorded as RESUME_REJECTED since the last request that authenticated
(`uf`); a further one changes nothing. `IFail` is the bound (it is not
repeated in `TypeOK`), and `SP_Fail` says that a request that authenticates is
always recorded and restores the allowance of the session it was sent to (the
ghost `last` carries the session). `FailMax = 1` in the cfg files stands for
the limit of the reference bridges, except in the Book configuration, where it
is 2. Restart voids the nonces, with what the book held about them, and
restores the allowance.

## Calls with no escalation pending (direct calls)

`Direct(s, k)` is a call that arrives in `(Att, None)`. It is not queued and
takes no key. If its permission is in the current scope it goes straight to
the runtime and leaves no event; if not, it is refused and recorded
(`TOOL_CALL_REJECTED`, reason `scope`). The session record does not change in
the first case, so the model's only trace of the call is the ghost `last`
(`call`, `fw`). `SP_Direct` reads it: a call goes straight to the runtime only
in `(Att, None)` and only within the scope, and a call outside the scope is
refused with an event. Mutants: a direct call outside the scope is forwarded;
it is refused without a record.

## Tuning the state space

The safety configurations name `VIEW SafetyView` in the cfg. A view is sound
here because states with the same view have the same futures and the checked
properties do not tell them apart: `last` (the request just answered) is
written by `Present` and `Direct` and read by no guard, and its checks are
step properties; the spent-nonce set and the countdown of a nonce that is
expired, voided or spent cannot matter (a nonce is never live again); the key
id of a nonce is read only together with its mark `ng`, so the key id of an
unmarked nonce cannot matter; the refusals noted for a nonce (`nr`) are read
only when a request naming it is accepted, which needs the nonce live; a
terminated session never changes, and the view keeps of it that it ended, why,
and what `I6` reads (its queue and its timers, all discarded at termination,
so they add no class). The approval countdown is per call and is not hidden. The step properties are evaluated on every transition, whatever
the view merges. A view cannot be used with the liveness configuration, which
runs without it; there `GhostOn = FALSE` keeps `last` at its initial value, so
that the ghost, which no liveness property reads, does not multiply the
states. The timer constants are not changed. Symmetry covers sessions only
(`Clients`, `Perms` and `Keys` are named literals in the module and the nonces
are ordered), so it stays in `BridgeContract.cfg`.

Soundness of the view, checked against what each property reads. The step
properties (`StepProps`) are evaluated on every transition out of every state
TLC expands, and the successor of two states with the same view has the same
view, so a step property is checked for every distinct view-class. `SP_Spent`
reads `nu` only to compare it before and after; `SP_Enter` and `SP_NoReplay`
read the nonce a request spends, which was live before (so its countdown, its
binding and its refusals are in the view); `SP_Fail` and `SP_Honest` read
`last` in the step that writes it. `SP_Direct` reads `last` before and after
the step: a call that goes straight to the runtime changes nothing but
`last`, so the state it leads to is never a new one under the view, the
states TLC expands never carry such a call in `last`, and the step that sends
one always changes `last`. The state invariants are evaluated on the first
state found in each class. `IBook`, `I11` and the liveness of a nonce depend
on the nonce book through `LiveSet`, the marks and the refusals of live
nonces, all functions of the view; `I6` reads of a terminated session exactly
what the view keeps of it. The other invariants that range over terminated
sessions (`TypeOK`, `I2`, `Ack`, `I10`, `I13`, `IRev`) read fields that
termination does not change, so they hold after it if they held before, in a
state whose fields the view shows. `TypeOK` reads `nu` (a subset of the
issued ids) and `I9` reads every countdown: each is a bound that a hidden
value can only violate if the value was out of bound when it was set, and the
values are only set by `Challenge` (to `TNonce`, mutant "a nonce outlives
T_nonce") and the timer decrement, while a live or visible value is checked
as it is. This is an argument, not a proof. The mutants run under the view
(all configurations of the mutant run except the liveness one). A run of the
smaller safety configurations without the `VIEW` line is the second check; the
recorded one (`docs/logs/tlc-2026-11-11/noview/`) is of the model before the
nonce was bound to a key id and has to be repeated.

### Coverage lost by the tuning

* The attacker (replay, forgery with `AdvKeys`, `SP_Honest`) runs only in
  `BridgeContractAttack.cfg`; the other configurations run with
  `AttackOn = FALSE`, so the two-session configuration has no attacker.
  `SP_NoReplay` does not depend on the attacker and runs everywhere.
* `BridgeContractAttack.cfg` and `BridgeContractBook.cfg` have one permission,
  one call key and `AllowFaults = FALSE`: attacker or a book above one
  interleaved with two calls, with log tampering or with a recovery fault is
  unchecked, and the cell `Quarantined` is not reached there (`Corrupt` never
  fires).
* `ObsMax = 2`: the attacker remembers at most two honest signatures, so an
  attack that needs three or more distinct remembered signatures is not
  explored.
* The attacker does not interleave sessions.
* More than one live nonce, and `FailMax` above one, are explored only in
  `BridgeContractBook.cfg`, with no attacker.
* Every configuration has `MaxRestarts = 1` and `QMax = 1`: a second restart
  and a drain of more than one call are not explored.

## Key lifecycle (I11-REVOKE)

The record of a session carries `rev` (revoked keys, a subset of `K`) and
`hard` (those revoked for compromise, a subset of `rev`); revoked keys stay in
`K` and a revocation is never undone. Actions: `Revoke(s, c, why)` with `why`
in `{rotation, compromise}` (KEY_REVOKED), `OperatorAddKey` (OPERATOR_ADD_KEY)
and `OperatorEnd` (OPERATOR_TERMINATION, also for a key-exhausted session). A
revocation of the key that a re-attach is verifying abandons the verification
whatever the reason (`Res` to `Det`, DETACHMENT, RESUME_PREPARED); otherwise a
compromise also detaches a connected client and a rotation only stops new
re-attach and join. `IRev` states both: a key revoked for compromise is not
connected, and no revoked key is being verified. `ExhR(r)` is key_exhausted:
every key in `K` is in `rev`. It is a side predicate: such a session keeps its
cell and serves no client action, but its timers keep running, a restart
treats it like any other session and a lost transport detaches it, so a
detached key-exhausted session ends after `T_detach` (or `T_total`) unless the
operator adds a key. A challenge is still answered and a request still
refused on such a session (neither answer may depend on the registry), which
is how the model reaches "a request refused on a key-exhausted session, the
key added by the operator, the request presented again". `Present` refuses a
revoked key and spends the nonce if the request authenticates. Checks: `IRev`,
`SP_Revoke` (monotone `K`, `rev`, `hard`), `SP_Join`, `SP_Register` and
`SP_Exhausted` (the key-exhausted session changes only by time, a restart or a
lost transport, a challenge or a refused request, the operator, or a new
key); `L1`, `L1Res`, `L2` and `CapEnds` have no key-exhaustion exit. `L1Res`
is L1 for the verification: a session does not stay in `Res`. It holds
because the key being verified is never revoked (`IRev`), so the session in
`Res` is never key-exhausted and `CompleteResume` stays enabled; the mutant "a
soft revocation leaves the session in Res" breaks exactly that. The abandoning
branch of `Revoke` needs `MaxEvents >= 7` to fire, so only the deep
configuration reaches it. That a refused request under a revoked key
spends its nonce has no property of its own: the key stays revoked, so the
request can never be accepted either way.

## Results

TLC reports no error in every configuration below, and all mutants are
killed, each by the property its label names. The logs are in
`docs/logs/tlc-rerun-2026-11-25/` (TLC build `2026.11.19.180144`, rev
`bc1b506`; jar sha256
`fdffef247f563ef6edbfd44958d2a82db79e7564e07cb673262d896353fa6713`;
container image `eclipse-temurin:21-jre`, digest
`sha256:d77e090ae1f6970c047b443c6f0a6c1358b0426d44432bb5a7753408cd43de0d`).
Each configuration ran alone, on one core and one worker, with no resume from a checkpoint, so every count is exact; run at most one large job at a time on a shared host. The Apalache run of `BridgeFull.tla` is in
`docs/logs/apalache-rerun-2026-11-25/`.

| Configuration | Generated | Distinct | Depth |
|---|---:|---:|---:|
| `BridgeContract` | 13,591,683 | 2,883,227 | 21 |
| `BridgeContractDeep` | 42,459,668 | 7,896,325 | 21 |
| `BridgeContractAttack` | 17,159,349 | 444,499 | 18 |
| `BridgeContractBook` | 2,668,635 | 425,861 | 18 |
| `BridgeContractLive` | 6,358,094 | 1,391,382 | 20 |
| `BridgeContractQueue` | 2,989,885 | 661,356 | 18 |
| `BridgeContractForward` | 11,321,712 | 2,259,734 | 20 |
| `BridgeContractLongHuman` | 3,714,583 | 821,343 | 18 |

The reach table (`tlc_coverage.py`) has not been rerun for this model; the
statements under "What each configuration reaches" are what the constants
imply, not a recorded result.

How to run it: `scripts/run-tlc-docker.sh LOGDIR mutants` runs the configurations it lists
and the mutants; `BridgeContractBook.cfg` and `tlc_coverage.py` are run with
the commands under "Running TLC".

| Configuration | Checks |
|---|---|
| `BridgeContract.cfg` (2 sessions, `MaxEvents = 2`, no attacker) | `Inv`, `StepProps` |
| `BridgeContractDeep.cfg` (1 session, `MaxEvents = 7`, no attacker) | `Inv`, `StepProps` |
| `BridgeContractAttack.cfg` (1 session, `MaxEvents = 5`, attacker, `ObsMax = 2`) | `Inv`, `StepProps` |
| `BridgeContractBook.cfg` (1 session, `MaxEvents = 5`, `LiveLimit = 2`, `MaxNonce = 3`, `FailMax = 2`) | `Inv`, `StepProps` |
| `BridgeContractLive.cfg` (1 session, `MaxEvents = 5`, fair, no view, ghost off) | `L1`, `L1Res`, `L2`, `CapEnds` |
| `BridgeContractQueue.cfg` (1 session, `MaxEvents = 5`) | `Inv`, `StepProps` |
| `BridgeContractForward.cfg` (1 session, `MaxEvents = 6`) | `Inv`, `StepProps` |
| `BridgeContractLongHuman.cfg` (1 session, `MaxEvents = 5`, `THuman = 6`) | `Inv`, `StepProps` |

All safety rows use `VIEW SafetyView` (see "Tuning the state space"); distinct
counts are therefore counts of view classes. Under a view with several workers
the number of view classes TLC visits is not reproducible to the last digit
(seen in the runs of 2026-11-11; the cause was not investigated): read counts as
sizes, not as values a rerun must match. The model is larger than the one of
the runs of 2026-11-11 (the binding of each nonce and the refusals noted for it are
state, and a refused request or call is one more way to spend an event), and
it grows faster with `MaxEvents`, so expect longer runs, the deep
configuration most of all. The attacker configuration has `MaxEvents = 5`,
against 7 in the runs of 2026-11-11, for that reason: the attacker's presentations
multiply the transitions out of every state, and each further event
multiplies the run several times over. The attempt "a request is refused on a
session whose only key was revoked for compromise, the operator adds the key,
the request is presented again" needs `MaxEvents = 7`: the deep configuration
reaches it (and checks it by `SP_NoReplay`, which needs no attacker); the
attacker configuration reaches the same attempt after a registration by a
client (`MaxEvents >= 4`) and after a soft revocation (`MaxEvents >= 5`).

Common constants: `TDetach = 4`, `THuman = 4`, `TCall = 3`, `TApprove = 2`,
`TNonce = 2`, `MaxNonce = 2`, `Clients = {c1, c2}`, `QMax = 1`, `TTotal = 6`,
`Allow = {p1}`, `MaxRestarts = 1`, `LiveLimit = 1`, `FailMax = 1`,
`AdvKeys = {x}`, `GhostOn = TRUE` (not in the liveness configuration), faults
enabled (not in the attacker and Book configurations), `DetPolicy = refuse`
except where a row says otherwise. The model assumes `TCall <= THuman` and
`TDetach <= TTotal`; `THuman <= TDetach` is only a recommendation and the last
row exceeds it. The attacker and Book configurations have `Perms = {p1}`,
`Keys = {k1}`, `AllowFaults = FALSE`.

### What each configuration reaches

`tlc_coverage.py` finds the cells of the product machine that no state of a
configuration is in (a probe invariant in `BridgeContractCover.tla` per cell)
and, from `-coverage 1`, the actions that generate no new state. Every action
of `Next` has to appear under its own name in TLC's report: the two forms of
a presentation are the actions `PresentHonest` and `PresentAdv` (their
quantifiers run over constant sets, so TLC names them), the script reports
their sum as `Present`, and it stops if TLC files any state under `Next`.
`python3 -I tlc_coverage.py --check` tests that parser without TLC.

By the constants alone: `PresentAdv` fires only where `AttackOn` is TRUE;
`SubmitAway` never fires under `DetPolicy = "refuse"`, where a refused call
changes nothing; `Corrupt` never fires where `AllowFaults` is FALSE, so the
cell `Quarantined` is not reached in the attacker and Book configurations; and
the two-session configuration, whose bound of 2 leaves one event per session
after the attach, cannot fire `Disconnect` (a detachment appends two events)
and reaches `Det` only through `Restart`, after which the bound leaves no room
for a request, so it does not reach `Res`. Which further cells and actions
each configuration reaches is a result of the run and is recorded with it.

### Is the verdict vacuous?

`tlc_mutants.py` holds one-line mutants of the spec (`--list` prints them
with the property and the configuration of each). Each mutant is labelled
with one property: a conjunct of `Inv`, a rule `SP_x` of `StepProps`, or a
liveness property. The script runs the mutant against that property alone
(for a rule it appends `Only_SP_x == [][\A s \in Sessions : SP_x(s)]_vars` to
the copy of the module), reads the name of the violated property from TLC's
error line and counts a kill only when TLC reports a violation of that
property. A survivor, a violation of another property, a parse or semantic
error and a timeout all fail the run. `--check-patches` (no TLC) checks that
every anchor applies exactly once, that every label names a property of the
spec and fits its configuration, and that every conjunct of `Inv`, every rule
of `StepProps` and every liveness property has a mutant labelled with it;
`CapEnds` is the declared exception (it follows from `L1`). With
`DIAGNOSE=1` a survivor is run again against every property, one by one, to
say what would have caught it.

Before the mutants, the unmodified spec is run with all its properties in
every configuration a mutant uses (base, queue, forward, forward with one
event more, deep and narrow, attacker, three client keys, book, narrow with
one client key and two events more, liveness) and has to pass in each; the log
has one `control` line per configuration and the sha256 of the module.

The mutant run uses `BridgeContract.cfg` as its base with one session, no
symmetry and `MaxEvents = 6` (not the bound of the cfg, which is 2), with
`VIEW SafetyView` and the attacker off. The other configurations are that base
with the changes named at the top of the script; those marked narrow have one
permission, one call key and no log tampering. The liveness mutants run as
`BridgeContractLive.cfg` does, without the view, with the ghost off and with
`MaxEvents = 5`. Dropping `WF_vars(Timeout(s))` from `FairSpec` makes L1 and
L2 fail (checked on the model of the runs of 2026-11-11).

## Invariants and where they are checked

| Paper | TLA+ | Notes |
|---|---|---|
| I1 | `I1` | A detached session holds the resume record of its detachment. |
| I2, I12 | `I2`, `SP_Forward` | Nothing is forwarded unless its `TOOL_CALL_DRAINED` is committed; forwarding only in `(Att,None)`. |
| I3 | `SP_Scope`, `SP_Direct` | The scope only narrows, in every cell; a call with no escalation pending goes to the runtime only within the scope, and is otherwise refused and recorded. (Enforced vs observed is not distinguished: both leave the scope unchanged. That the scope is within the scope at attach is a type bound in `TypeOK`, not a separate invariant.) |
| I4, I9, I11 | `SP_Enter`, `I9` | Entering `Res`, or growing the client set, needs an authentic request (registered key, a signature that `Verifies`, a nonce issued for that key), a live unspent nonce, an acknowledged prefix; the nonce is spent by it; a nonce never outlives `TNonce`. The prefix is an abstract verdict; the signature is a possession predicate (UF assumed). |
| I11, key binding and replay | `I11`, `SP_Honest`, `SP_NoReplay`, `SP_Spent` | A nonce is good only for the key it was issued for, registered then; an accepted request was presented by an honest client; a refused request is never accepted later; a spent nonce stays spent; a challenge is answered the same way for every key id. |
| I11 (f), (g) | `IBook`, `SP_Issue`, `IFail`, `SP_Fail` | At most `LiveLimit` live nonces, a challenge never evicts a live one; unauthenticated failures are recorded at most `FailMax` per period, a request that authenticates is always recorded and restores the allowance. |
| I5 | `SP_Chain` | `Att` is entered only on an intact chain (`Corrupt` stands for tampering). |
| I6 | `I6`, `SP_I6` | A terminated session has an empty queue, no countdown and no live nonce, and never changes again. |
| I7 | `SP_I7` | The cell changes only with new committed events (`n` grows). |
| I8 | not modelled | The transport replay flag is a rejection like any other. |
| I10 | `I10`, `SP_Version` | Version `+1` exactly when the scope strictly narrows. |
| I13 | `I13`, `SP_Drain`, `SP_Appr`, `Timers` | Queue bound; drain only in `(Att,None)`, only in-time, approved, permitted calls; the approval of a call is recorded once, at the resolution of its escalation, and only runs down. |
| I14 | `SP_Drain` | A call is drained only with an approving answer of matching hash. |
| I15 | `I15`, `SP_Shrink`, `SP_Register` | `C` within `K`; `Att` iff `C` is non-empty; `Res` iff a key is being verified; a partial departure keeps `Att`; keys are registered only through a connected client. |
| I11-REVOKE | `IRev`, `SP_Revoke`, `SP_Join`, `SP_Exhausted` | See "Key lifecycle". |
| L1, L2 | `L1`, `L1Res`, `L2` | Under fair `Tick`, `Timeout`, `CompleteResume`; a detached session re-attaches, ends or is quarantined; a session does not stay in `Res`. |
| Rule Q | `EndCause`, `SP_Quarantine` | A chain or recovery failure sets `quar`; a quarantined session changes only by an operator's end; no session ends without a cause. |
| Timers, `T_total` | `Timers`, `SP_Timeout`, `SP_Total`, `SP_LeaveDet`, `CapEnds` | Each countdown runs exactly where it should; a session ends by timeout only when `T_detach`, `T_total` or `T_human` has run out, and the timeout is due as soon as one has (`ENABLED Timeout`); the cap is never reset and runs down only in `Det`. `CapEnds` follows from `L1` and is not an independent check. |
| Forwarding acknowledgement | `Ack`, `SP_Forward` | Only a forwarded call is delivered; a delivered call is never forwarded again; after a restart an undelivered one is. |
| Detached-call policy | `SP_Allow`, `SP_Drain` | An operator-drained call is on the allowlist and in scope; a held call needs its own answer. |

## Abstractions

* **The log.** The log is represented by its length `n` and the state it
  determines. A transition appends its events and changes the state in one
  step (the committed batch of I12). A crash between the append and the
  in-memory change is equivalent to the same step followed by `Restart`,
  which rebuilds the state from the log. This covers every crash point only
  on the assumption that a batch is atomic: a crash inside a batch of several
  events (a torn batch) is not modelled.
* **Cryptography.** No hash chain and no signature bytes. A request is a key,
  a signature record, a claimed nonce and a prefix verdict; the signature is
  checked by the possession predicate against the attacker above. The replay
  of unseen events is not modelled. Unforgeability of the scheme and the
  bytes that are signed are covered by the Python suite, its mutants and the
  vectors, not by TLC. Challenge issuance is not an event and nonces are
  volatile (a restart voids them).
* **One presentation.** `Present` stands for both a join and a re-attach (the
  cell decides which), and a refusal carries no reason: the reason table and
  the rule that answers do not tell an outsider why are outside the model,
  except for the challenge (`I11`).
* **Time.** Countdowns decremented by `Tick`; no wall clock, no skew (A6).
* **Queue order.** The queue is a set: order is not safety-relevant here.
* **Restart.** Atomic for all sessions; bounded by `MaxRestarts`. Recovery
  rule 3 (a timeout that elapsed during the downtime ends the session at
  recovery) is not modelled, because no time passes during `Restart`; rule 4
  (a chain that does not verify quarantines the session) is.

## Limitations

* **Bounded state space.** Two sessions with `MaxEvents = 2` allow only one
  state-growing action per session after attach (the two-session run mostly
  checks the interaction of the global `Tick` and `Restart` across sessions),
  two client keys and at most two challenges per session. The depth comes from
  the one-session runs. Sessions interact only through `Tick` and `Restart`,
  which is an argument for, not a proof of, independence. Results do not
  extend to unboundedly many sessions, keys, permissions or restarts.
* **Fairness.** L1 and L2 hold only under weak fairness of `Tick`, `Timeout`
  and `CompleteResume` (axiom A6). The event bound `MaxEvents` also bounds the
  `Det -> Res -> Det` re-attach cycle, so the model cannot exhibit a session
  that cycles forever without terminating or attaching. L1 is therefore
  checked in its per-episode form (`L1`: a detached session leaves `Det` or
  terminates; `L1Res`: a session in `Res` leaves it), not in the stronger form
  of the paper ("re-attaches to `Att` or terminates").
* **Timer bounds are not deadlines.** A countdown at zero enables `Timeout`
  and nothing else forces it: "within `T_detach`" is checked as "the timeout
  is due when the countdown is at zero" (`Timers`), "no timeout before that"
  (`SP_Timeout`) and "it eventually fires" (`L1`, `L2`), not as a bound on the
  ticks that pass.
* **Rules that restate a guard.** Several rules of `StepProps` say again what
  the guard of one action says (the drain conditions, the registration of a
  key, the answer flag of I14). They catch an edit to one of the two copies,
  not a design error. The properties that are independent of the action text
  are `I1`, `I11`, `I15`, `Timers`, `IRev`, `I6`, `EndCause`, `SP_Honest`,
  `SP_NoReplay`, `SP_Total` and the liveness properties.
* **Safety only under no Byzantine faults.** A4 (trusted bridge) is assumed.
  Faults are limited to log tampering and recovery failure.
* **No multi-hop, no PACE/GEC composition.** The compositional arguments in
  the appendix on compositional safety are paper-level; they are not part of
  this model.
* **Checkpoints** (I-CHECKPOINT, a SHOULD) are not modelled.
* **Simplifications of the later rules.** Time does not pass during `Restart`,
  so `T_total` counts no bridge downtime (the Python bridge does, and vector V32
  checks it). The detached-call policies are checked one per configuration.
  `TOOL_CALL_COMPLETED` changes no state and is not modelled. An operator-drained
  call may be forwarded at any later point while `h = None`, which
  over-approximates the Python bridge, which forwards it at once. The model cannot
  exhibit an unbounded detach/re-attach cycle (`MaxEvents`), so the cap is checked
  as a safety property (never reset, runs down only in `Det`, the timeout due
  when it is used up). `T_detach` starts afresh when a verification is
  abandoned (`Res` to `Det`). A re-forward after a restart needs more events
  than the shipped configurations allow; the deep and narrow configuration of
  the mutant run (`MaxEvents = 11`) reaches it, and its control run is the only
  run of the unmodified model that does.

## Findings

1. **L1 wording.** The paper states L1 as "re-attaches successfully (through
   `Res` to `Att`) or reaches the terminal cell". What TLC verifies is that every
   `Det` episode ends in `Res` or in termination; reaching `Att` needs
   `CompleteResume`, and a client that keeps disconnecting during verification
   restarts `T_detach` each time, so the stronger statement is not a liveness
   property of the bridge without an assumption on the client.
2. **Delivery after a crash.** Recovery rule 5 says delivery of queued calls
   is at-least-once, never silently lost. Without an acknowledgement a call
   that was committed as drained and then lost to a crash before the forward
   was never forwarded again. The specification now has the acknowledgement
   (`TOOL_CALL_DELIVERED`) and the model shows the repair: `Forward` is
   enabled again after a restart for any drained call not delivered, and never
   for a delivered one.
3. **Quarantine and liveness.** With rule Q a quarantined session stays in its
   last cell, so `L1` and `L2` as first stated failed on a quarantined `Det`
   session. The properties now name quarantine as an exit, as the paper does.
4. **A refused request accepted later.** With a nonce that named no key, a
   request refused because its key was not registered kept its nonce, and the
   same bytes were accepted once the key was registered. The property the
   model had (the accepted signature was made by an honest holder) admitted
   that trace, because a replayed honest signature satisfies it. The nonce is
   now bound to a key id at issue, and the properties are the ones the prose
   needs: `SP_Honest` (presented by an honest client) and `SP_NoReplay`
   (refused once, never accepted).
5. **A session held in `Res`.** A soft revocation of the only key while its
   re-attach was being verified left the session key-exhausted in `Res`, where
   no timer runs and `CompleteResume` is disabled, so it stayed there for
   ever; L1 was checked only for `Det`. A revocation now abandons the
   verification whatever its reason, and `L1Res` states the property.
6. **A lapsed approval renewed.** One approval countdown per session meant
   that the resolution of a later escalation renewed the approval of a call
   whose own approval had lapsed. The countdown is now per call, set once at
   the resolution of the call's escalation (`SP_Appr`).
