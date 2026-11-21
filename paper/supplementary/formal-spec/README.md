# Bridge Contract — TLA+ model

`BridgeContract.tla` models the product machine of the paper (Section 5.1):
attachment `{Att, Det, Res}` x human `{None, Pend}` x lifecycle
`{Active, Terminated}`, plus quarantine on a chain failure, the cumulative
detachment cap `T_total`, the detached-call policy and the forwarding
acknowledgement, with narrow-only authority (I3, I10), a possession predicate on the
resume signature against an explicit attacker (I11), a bounded nonce book and a
bounded record of unauthenticated failures (I11 (f), (g)), token TTL (I9),
durable append and restart recovery (I12), and the tool queue with
idempotency keys, call expiry and approval freshness (I13). Time is a set of
countdowns decremented by `Tick`.

| File | Purpose |
|---|---|
| `BridgeContract.tla` | The model, its invariants (`Inv`), step properties (`StepProps`) and liveness (`L1`, `L2`). |
| `BridgeContract.cfg` | Safety, 2 sessions x 2 principals x 2 permissions, `MaxEvents = 2`, symmetry on sessions. |
| `BridgeContractDeep.cfg` | Safety, 1 session, `MaxEvents = 7`. |
| `BridgeContractAttack.cfg` | Safety with the attacker on (`AttackOn`), 1 session, one permission and one call key, no log tampering, `MaxEvents = 7`, `ObsMax = 2`. |
| `BridgeContractLive.cfg` | `L1`, `L2` under fair scheduling (`FairSpec`), 1 session, `MaxEvents = 5`. |
| `BridgeContractQueue.cfg`, `BridgeContractForward.cfg` | Safety under the `queue` and `forward` detached-call policies. |
| `BridgeContractLongHuman.cfg` | Safety with `THuman > TDetach`. |
| `BridgeContractCover.tla`, `tlc_coverage.py` | Which cells and actions each configuration reaches (probe invariants and `-coverage`); see the next section. |
| `tlc_mutants.py` | Breaks the spec one line at a time and checks TLC reports a violation each time. |

## Running TLC

```bash
curl -L -o tla2tools.jar https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar
java -cp tla2tools.jar tla2sany.SANY BridgeContract.tla                       # parse
for c in BridgeContract BridgeContractDeep BridgeContractLive; do
  java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -config $c.cfg -workers auto -deadlock BridgeContract.tla
done
TLA2TOOLS=$PWD/tla2tools.jar python3 -I tlc_mutants.py                        # sanity mutants
```

`-deadlock` turns deadlock checking off: bounded actions legitimately stop.

## Attacker model (I11)

A signature is a record `[by, nonce, pre]`: the key that signed, the nonce and
the prefix verdict it covers. `Verifies(key, sig, claimed, pre)` holds iff
`sig.by = key`, `sig.nonce = claimed` and `sig.pre = pre`; this predicate is
the unforgeability assumption UF (only the holder of a key produces a
signature that verifies for it), stated in one place and not model-checked.
An honest client (`Present` with source "honest") signs with a key in
`Clients` and its signature goes on the wire (`obs`, per session). The
attacker (source "adv") observes the log and the wire, so it can resubmit any
signature in `obs`, builds its own with the keys in `AdvKeys` (the constant,
disjoint from `Clients`), names any registered or unregistered key, any
nonce number and any prefix verdict, and so replays and reorders; it never
holds a key of `Clients`. The step property labelled "I4, I9, I11, I15" now
includes `NoForgery`: an accepted request spends a live nonce and its
(key, nonce, verdict) signature is in `obs`, that is, produced by an honest
holder (or it is an honest request, whose signature is by construction the
holder's). Mutants: the attacker holds a client key; a signature verifies under
any key, or is not bound to its nonce, or not to the prefix verdict.

Two model switches keep the state space small (see "Tuning the state space").
`AttackOn = FALSE` removes the attacker's moves and the wire record; the
configurations that do not concern the attacker run so, and
`BridgeContractAttack.cfg` runs with it on. `ObsMax` bounds how many of the
honest signatures the attacker remembers: an honest request may or may not be
kept (a nondeterministic choice), so the attacker may keep any `ObsMax` of the
signatures it saw, and replays one of them at a time. The bound loses attacks
that combine more than `ObsMax` different remembered signatures.

Not in the attacker: stealing a client key (A7; I11-REVOKE), another session
(the wire format binds the session id; `obs` is per session), the chain (I5),
the transport (I8), operator signatures and the attach proof. Replaying an
observed request whose signature verifies is recorded each time (the text of
(g) records every failure of an authentic request), so the log grows with the
attacker's replays; (g) bounds only failures before authentication.

## Nonce book and unauthenticated failures (I11 (f), (g))

The nonce book is the per-session set of issued nonces: `nb` (a countdown per
nonce id), `nu` (spent ids), `nid` (issued). A nonce is live iff issued,
unexpired and unspent. `LiveLimit` bounds the live nonces; `Challenge` is
disabled when the book is full (the bridge refuses the challenge) and never
invalidates a live nonce: `IBook` is the bound, and the step property labelled
"I11f" is the no-eviction rule. `FailMax` bounds the failures before
authentication that are recorded as RESUME_REJECTED since the last request whose
signature verified (`uf`); a further one changes nothing. `IFail` states the
bound, that a request whose signature verifies is always recorded and that it
restores the allowance (for the session that presented last, so the last part is
exact only in the one-session configurations and the mutant runs). `LiveLimit
= 1` and `FailMax = 1` in the cfg files stand for the limit of the reference
bridges. Restart voids the nonces and restores the allowance.

## Tuning the state space

The safety configurations name `VIEW SafetyView` in the cfg. A view is sound
here because states with the same view have the same futures and the checked
properties do not tell them apart: `last` (the presentation just taken) is
written by `Present` and read by no guard, and its checks are step properties;
the spent-nonce set and the countdown of a nonce that is expired, voided or
spent cannot matter (a nonce is never live again); the approval countdown is
read only by `Drain` for a call queued during an escalation, and every
`Resolve` sets it afresh; a terminated session never changes. The step
properties are evaluated on every transition, whatever the view merges. A view
cannot be used with the liveness configuration, which runs without it. The
timer constants are not changed. Symmetry covers sessions only (`Clients`,
`Perms` and `Keys` are named literals in the module and the nonces are
ordered), so it stays in `BridgeContract.cfg`.

Soundness of the view, checked against what each property reads. The step
properties (`StepProps`) are evaluated on every transition out of every state
TLC expands, and the successor of two states with the same view has the same
view, so a step property is checked for every distinct view-class; it reads
`nu` only to compare it before and after (the spent set only grows; the
accepted request's nonce is in `nu'` and was live before, so its countdown is
visible), and `last` only in the step that writes it. The state invariants
are evaluated on the first state found in each class. `IBook`, `IFail` and
the liveness of a nonce depend on the nonce book through `LiveSet`, which is a
function of the view (a nonce is live iff its visible countdown is positive).
`TypeOK` reads `nu` (a subset of the issued ids), `I9` reads every countdown
and `Timers` reads the approval countdown: each is a bound that a hidden value
can only violate if the value was out of bound when it was set, and
the values are only set by `Challenge` (to `TNonce`, mutant "a nonce outlives
T_nonce"), `Resolve` and the timer decrement, while a live or visible value is
checked as it is. This is an argument, not a proof. Two checks back it. The
mutants run under the view (all configurations of the mutant run except the
liveness one), and each is still killed. And the three safety configurations
that are small enough to run without it were also run without the view
(`docs/logs/tlc-2026-11-11/noview/`, same cfg with the `VIEW` line removed): each
reports no error, with 1,660,552 distinct states for `BridgeContractQueue.cfg`
(228,468 with the view), 2,097,848 for `BridgeContractLongHuman.cfg` (275,159)
and 6,562,987 for `BridgeContractForward.cfg` (685,335). The two-session,
deep and attacker configurations were not run without the view: they are too
large for it.

### Coverage lost by the tuning

* The attacker (replay, forgery with `AdvKeys`, the `NoForgery` step property)
  runs only in `BridgeContractAttack.cfg`; the other configurations run with
  `AttackOn = FALSE`, so the two-session configuration has no attacker.
* `BridgeContractAttack.cfg` has one permission, one call key and
  `AllowFaults = FALSE`: attacker interleaved with the tool queue, drain or
  forwarding is unchecked, and with no `Corrupt` the cell `Quarantined` is not
  reached there (`Corrupt` and `SubmitAway` never fire).
* `ObsMax = 2`: the attacker remembers at most two honest signatures, so an
  attack that needs three or more distinct remembered signatures is not
  explored.
* The attacker does not interleave sessions (as before).
* `IBook` and `IFail` stay in `Inv` for every configuration; the nonce book
  and the failure record are exercised in all of them by honest and
  unauthenticated requests, but a replayed authentic request only in the
  attacker configuration.

## Key lifecycle (I11-REVOKE)

The record of a session carries `rev` (revoked keys, a subset of `K`) and
`hard` (those revoked for compromise, a subset of `rev`); revoked keys stay in
`K` and a revocation is never undone. Actions: `Revoke(s, c, why)` with `why`
in `{rotation, compromise}` (KEY_REVOKED; a compromise also detaches a
connected client and abandons a re-attach it is verifying), `OperatorAddKey`
(OPERATOR_ADD_KEY) and `OperatorEnd` (OPERATOR_TERMINATION, now also for a
key-exhausted session). `ExhR(r)` is key_exhausted: every key in `K` is in
`rev`. It is a side predicate: such a session keeps its cell and serves no client
action, but its timers keep running, a restart treats it like any other
session and a lost transport detaches it, so a detached key-exhausted session
ends after `T_detach` (or `T_total`) unless the operator adds a key. `Present` refuses a
revoked key but spends the nonce it names. New checks: `IRev`, the step
properties on monotone `K`/`rev`/`hard`, on joiners, on key registration and on
the key-exhausted session (it changes only by time, a restart or a lost
transport, the operator, or a new key); `L1`, `L2` and `CapEnds` have no
key-exhaustion exit;
`tlc_mutants.py` has the I11-REVOKE, key_exhausted and OPERATOR_ADD_KEY mutants.
Revocation of the key being verified in `Res` is a modelling choice (the
paper is silent): a hard revocation abandons the verification, a soft one does
not. The abandoning branch needs `MaxEvents >= 7` to fire, so only the deep
configuration reaches it.

## Results (TLC build `2026.11.06.222357`, TLC jar revision `d8fb231` (not a revision of this repository); OpenJDK 21; 8 cores; Docker; logs in `docs/logs/tlc-2026-11-11/`)

The jar is the one at the v1.8.0 release URL above (sha256
`e1f11b75c4b5bc4478ba0ac5cb6ae28e40a01b0016bc33e0aa97da22dfdbcd7f`); its
banner is a nightly-style build number, not a release number such as 2.19. The
container image was `eclipse-temurin:21-jre`, digest
`sha256:0b99b3376fbb50dbf9c0af8535fdd5b8eb0d3fdfc8b1e4967f383b6919f6901a`. `scripts/run-tlc-docker.sh docs/logs/tlc-2026-11-11 mutants` reproduces the run.
Times are wall-clock seconds of the container, including JVM start, on a host
shared with other jobs.

SANY parses the module. TLC reports "No error has been found" in every configuration.

| Configuration | Checks | States generated | Distinct | Depth | Time |
|---|---|---:|---:|---:|---:|
| `BridgeContract.cfg` (2 sessions, `MaxEvents = 2`, no attacker) | `Inv`, `StepProps` | 881,440 | 210,466 | 20 | 1 min 5 s |
| `BridgeContractDeep.cfg` (1 session, `MaxEvents = 7`, no attacker) | `Inv`, `StepProps` | 9,713,752 | 2,208,460 | 19 | 2 min 50 s |
| `BridgeContractAttack.cfg` (1 session, `MaxEvents = 7`, attacker, `ObsMax = 2`) | `Inv`, `StepProps` | 18,875,492 | 1,082,581 | 21 | 4 min 26 s |
| `BridgeContractLive.cfg` (1 session, `MaxEvents = 5`, fair, no view) | `L1`, `L2`, `CapEnds` | 3,792,867 | 1,479,144 | 21 | 4 min 28 s |
| `BridgeContractQueue.cfg` (1 session, `MaxEvents = 5`) | `Inv`, `StepProps` | 890,183 | 228,468 | 17 | 20 s |
| `BridgeContractForward.cfg` (1 session, `MaxEvents = 6`) | `Inv`, `StepProps` | 2,868,553 | 685,335 | 18 | 46 s |
| `BridgeContractLongHuman.cfg` (1 session, `MaxEvents = 5`, `THuman = 6`) | `Inv`, `StepProps` | 1,069,099 | 275,159 | 17 | 20 s |

All safety rows use `VIEW SafetyView` (see "Tuning the state space"); the
distinct counts are therefore counts of view classes. The earlier model, which
had no attacker and no view, had 18.6 million distinct states in the deep
configuration; the first attempt to add the attacker without the view did not
finish that configuration in five hours (over 100 million distinct states and
a queue of 30 million), which is why the attacker is confined to its own
configuration.

A second full run of the same configurations on the same model
(`docs/logs/tlc-freeze-2026-11-11/`, which also runs the no-change control of
`tlc_mutants.py` and again kills every mutant) reports the same counts for
every configuration except the two-session one, where it reports 881,106
states generated and 210,408 distinct. Under a view with several workers the
number of view classes TLC visits is not reproducible to the last digit (the
cause was not investigated); read the counts in the table as sizes, not as
values a rerun must match. The verdicts agree.

Common constants: `TDetach = 4`, `THuman = 4`, `TCall = 3`, `TApprove = 2`,
`TNonce = 2`, `MaxNonce = 2`, `Clients = {c1, c2}`, `QMax = 1`, `TTotal = 6`,
`Allow = {p1}`, `MaxRestarts = 1`, `LiveLimit = 1`, `FailMax = 1`,
`AdvKeys = {x}`, faults enabled (not in the attacker configuration),
`DetPolicy = refuse` except where a row says otherwise. The model assumes
`TCall <= THuman` and `TDetach <= TTotal`; `THuman <= TDetach` is only a
recommendation and the last row exceeds it. The attacker configuration has
`Perms = {p1}`, `Keys = {k1}`, `AllowFaults = FALSE`.

### What each configuration reaches

`tlc_coverage.py` finds the cells of the product machine that no state of a
configuration is in (a probe invariant in `BridgeContractCover.tla` per cell)
and, from `-coverage 1`, the actions that generate no new state
(`docs/logs/tlc-2026-11-11/coverage.jsonl`). All cells, including the key_exhausted
probe (`Probe_KeyExhausted`), are reached in every one-session configuration
except the attacker configuration, which never reaches `Quarantined` (it has
no `Corrupt`; `Corrupt` and `SubmitAway` never fire there). In the
two-session configuration key_exhausted is reached too (`Revoke` fires).
Not reached there: `(Res, None)` and
`(Res, Pend)`, and the configuration also never fires
`Disconnect`, `Resolve`, `Submit`, `Drain`, `Forward`, `Answer`, `ExpireCall`,
`Extend`, `OperatorAddKey`, `OperatorEnd` or `CompleteResume` (a detachment appends two events,
more than its bound of 2). `Deliver` fires only in `BridgeContractDeep.cfg`.
`SubmitAway` never fires under `DetPolicy = "refuse"`, where a refused call
changes nothing.

### Is the verdict vacuous?

`tlc_mutants.py` defines one-line mutants (a detach or restart without a
resume record, a narrowing without a version bump, a widening applied, a cell
change without an event, an unauthentic request accepted, an expired nonce
accepted or issued, a spent nonce accepted again, an accepted nonce not
consumed, the prefix not checked, a corrupt chain verified, draining while
detached, draining without scope revalidation, approval expiry or the answer,
forwarding before the DRAINED event, an unbounded queue, a termination that
changes the scope, `T_detach` running in `Res`, a partial departure that
detaches, an unregistered key that is authentic, a key registered without a
connected client, a resume that attaches nobody, a restart that keeps the
client set, a chain or recovery failure that terminates instead of
quarantining, a quarantined session that keeps ticking or is touched by a
restart, a cap that is reset by a disconnect or a restart or that counts time
attached, a delivered call forwarded again, a forward during an escalation, a
forward that ignores the allowlist, a held call drained unanswered; for the key
lifecycle: a revoked key accepted, a revocation that removes the key from `K` or
accepts a key outside it, a hard revocation that leaves the client connected,
revoking the last client without detaching, a hard revocation that does not
abandon a verification, a revoked client that registers a key, a key_exhausted
session that serves client operations, one whose timers stop or whose
timeout does not fire (liveness, with `BridgeContractLive.cfg` settings),
OPERATOR_ADD_KEY on a session that is not key_exhausted or that clears the
revocation markers). **Status: all were killed** by TLC on the revision recorded in `docs/logs/tlc-2026-11-11/` (`mutants.log`: every mutant killed, none survived); the run includes the key-exhausted timer change and the two key_exhausted timer mutants (liveness) (each run on a
one-session configuration; the acknowledgement mutants need a deeper, narrower
one, set in the script). Dropping `WF_vars(Timeout(s))` from `FairSpec` makes
L1/L2 fail on this model as well (checked with `BridgeContractLive.cfg`).
The mutant run uses `BridgeContract.cfg` as its base with one session, no
symmetry and `MaxEvents = 6` (not the bound of the cfg, which is 2), with
`VIEW SafetyView` and the attacker off; the attacker-model mutants run with
`AttackOn = TRUE` and `ObsMax = 2` on that base (two permissions, two call
keys, faults on), a larger configuration than `BridgeContractAttack.cfg`; the
liveness and timer mutants run as in `BridgeContractLive.cfg`, without the
view and with `MaxEvents = 5`; the acknowledgement mutants run on the deeper,
narrower configuration set in the script. 
## Invariants and where they are checked

| Paper | TLA+ | Notes |
|---|---|---|
| I1 | `I1` | A detached session holds the resume record of its detachment. |
| I2, I12 | `I2`, step property | Nothing is forwarded unless its `TOOL_CALL_DRAINED` is committed; forwarding only in `(Att,None)`. |
| I3 | `I3`, step property | The scope only narrows, in every cell. (Enforced vs observed is not distinguished: both leave the scope unchanged.) |
| I4, I9, I11 | step property, `I9` | Entering `Res`, or growing the client set, needs an authentic request (registered key, a signature that `Verifies` and an honest holder produced), a live unspent nonce, an acknowledged prefix; the nonce is spent by it; a nonce never outlives `TNonce`. The prefix is an abstract verdict; the signature is a possession predicate (UF assumed). |
| I11 (f), (g) | `IBook`, `IFail`, step property | At most `LiveLimit` live nonces, a challenge never evicts a live one; unauthenticated failures are recorded at most `FailMax` per period, a verifying request is always recorded and restores the allowance. |
| I5 | step property | `Att` is entered only on an intact chain (`Corrupt` stands for tampering). |
| I6 | step property | A terminated session never changes again. |
| I7 | step property | The cell changes only with new committed events (`n` grows). |
| I8 | not modelled | The transport replay flag is a rejection like any other. |
| I10 | `I10`, step property | Version `+1` exactly when the scope strictly narrows. |
| I14 | step property | A call is drained only with an approving answer of matching hash. |
| I15 | `I15`, step property | `C` within `K`; `Att` iff `C` is non-empty; `Res` iff a key is being verified; a partial departure keeps `Att`; keys are registered only through a connected client. |
| I13 | `I13`, step property | Queue bound; drain only in `(Att,None)`, only in-time, approved, permitted calls. |
| L1, L2 | `L1`, `L2` | Under fair `Tick`, `Timeout`, `CompleteResume`; a detached session re-attaches, ends or is quarantined. |
| Rule Q | `EndCause`, step property | A chain or recovery failure sets `quar`; a quarantined session changes only by an operator's end; no session ends without a cause. |
| `T_total` | step property, `CapEnds` | The cap is never reset and runs down only in `Det`; when it is used up the session leaves `Det`, ends or is quarantined. |
| Forwarding acknowledgement | `Ack`, step property | Only a forwarded call is delivered; a delivered call is never forwarded again; after a restart an undelivered one is. |
| Detached-call policy | step property | An operator-drained call is on the allowlist and in scope; a held call needs its own answer. |

## Abstractions

* **The log.** The log is represented by its length `n` and the state it
  determines. A transition appends its events and changes the state in one
  step (the committed batch of I12). A crash between the append and the
  in-memory change is equivalent to the same step followed by `Restart`,
  which rebuilds the state from the log, so all crash points are covered.
* **Cryptography.** No hash chain and no signature bytes. A request is a key,
  a signature record, a claimed nonce and a prefix verdict; the signature is
  checked by the possession predicate against the attacker above. The replay
  of unseen events is not modelled. Unforgeability of the scheme and the
  bytes that are signed are covered by the Python suite, its mutants and the
  vectors, not by TLC. Challenge issuance is not an event and nonces are
  volatile (a restart voids them).
* **Time.** Countdowns decremented by `Tick`; no wall clock, no skew (A6).
* **Queue order.** The queue is a set: order is not safety-relevant here.
* **Restart.** Atomic for all sessions; bounded by `MaxRestarts`.

## Limitations

* **Bounded state space.** Two sessions with `MaxEvents = 2` allow only one
  state-growing action per session after attach (the two-session run mostly
  checks the interaction of the global `Tick` and `Restart` across sessions),
  two client keys and at most two challenges per session. The depth comes from
  the one-session run (`MaxEvents = 7`, 2,208,460 view classes). Sessions interact only through `Tick` and `Restart`, which is an
  argument for, not a proof of, independence. Results do not extend to
  unboundedly many sessions, keys, permissions or restarts.
* **Fairness.** L1 and L2 hold only under weak fairness of `Tick`, `Timeout`
  and `CompleteResume` (axiom A6). The event bound `MaxEvents` also bounds the
  `Det -> Res -> Det` re-attach cycle, so the model cannot exhibit a session
  that cycles forever without terminating or attaching. L1 is therefore
  checked in its per-episode form (a detached session leaves `Det` or
  terminates), not in the stronger form of the paper ("re-attaches to `Att` or
  terminates").
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
  as a safety property (never reset, runs down only in `Det`) and as `CapEnds`.

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
