# Language-neutral test vectors

One scenario per `Vnn.json`. A runner builds a bridge, creates the session
from `session`, applies `actions` in order, then checks `expect`. A vector
whose identifier ends in a letter (`V62b`) sits next to the vector it
extends; a runner reads every file whose name starts with `V`.

## Schema

```
{ "id", "title", "covers": [...],
  "requires": ["checkpoint"],   // optional; see below
  "config":  { t_detach, t_human, t_call, t_total, t_approve, t_nonce, q_max,
               detached_calls, detached_allow }   // seconds / count; optional, defaults below
  "session": { session_id, principal_id, authority_scope, client_key_id,
               scheme?, grant?, possession? },
               // scheme: ed25519 (default) or ecdsa-p256, for every client key of the vector;
               // grant: ok (default), none, forged, other-session, wider-scope,
               //   other-key (a grant for another public key under the same key id),
               //   other-bridge (a grant made for a different bridge);
               // possession: ok (default), none, wrong-key (a signature by another key),
               //   other-bridge (a proof made for a different bridge)
  "actions": [ {"do": ..., ...} ],
  "expect":  { "events": [kinds], "cell": [...], "scope_version": n,
               "queue": [keys], "forwarded": [keys],
               "forwarded_calls": {key: {tool, permission, content}}, "clients": [key ids],
               "quarantined": bool, "reverts": n, "last_event_payload": {k: v},
               "key_exhausted": bool, "revoked": [key ids, sorted],
               "registry": [key ids registered in storage, sorted] }   // or {"config_error": true}
}
```

Defaults: `t_detach` 1800, `t_human` = `t_detach`, `t_call` = `t_human`,
`t_total` = 4 x `t_detach`, `t_approve` 900, `t_nonce` 60, `q_max` 64. The clock starts at 1000 and moves
only on `advance`. `config_error: true` means constructing the bridge with
`config` must fail (`T_call <= T_human` and `T_detach <= T_total` are MUSTs;
`T_human` may exceed `T_detach`). `attach_refused: true` means the attach
with the named `grant` and `possession` must be refused and commit nothing;
`attach_reason` names the reason, `grant_invalid` (default) or
`possession_invalid`, and the runner checks nothing else. `quarantined: true` means the session is
frozen by a chain failure: its cell is the last one it had, and it accepts no
operation.

Key identifiers are scoped to a session. `attach_other` (`session_id`,
`client`, optional `principal_id`) attaches a second, validly granted session
on the same bridge whose client key carries the key id `client`; a
`reattach` with `proof: "other-session-key"` and `from_session` signs with that
second session's key under the same key id. A `reattach`, `join` or
`add_client` action with `nonce: "other-session"` and `from_session` presents a
nonce that the bridge issued for that second session, and must be refused as an
unknown nonce. `expect.other_events` maps a
second session's id to its event kinds. `tamper_registry` (`client`, `how`:
`other-key`, `extra` or `missing`) damages the key registry in storage:
`other-key` replaces the registered public key, `extra` registers a key the
log does not record, `missing` removes the entry; recovery must repair the
registry from the log in all three cases (the log is the source of truth), and
`expect.registry` lists the key ids registered afterwards.

Any action may carry `times: n`, which applies it n times in a row (each
application is checked against the action's `error` flag).

`requires: ["checkpoint"]` marks a vector that needs I-CHECKPOINT emission and
reads `n_checkpoint` and `t_checkpoint` from `config`. A runner for a
bridge without emission skips such a vector (the Rust crate does); every
other vector runs with checkpoints off, whatever `config` says.

`cell` is `["Att"|"Det"|"Res", "None"|"Pend"]`, or `["Terminated"]`.
`events` is the whole committed log of the session, kinds only, in order.
`clients` is the connected client set, sorted.

## Rules the vectors pin

A challenge names the key id the nonce is for, and the nonce is bound to it:
only a request that names that key id can use it, and only if the key was a
registered, unrevoked key of the session when the nonce was issued. The
bridge answers a challenge in the same way for every key id (a nonce of the
same form and lifetime, counted against the same per-session limit). A
request that presents a nonce issued for another key id, or for its own key
id before the key was registered, is answered `bad_signature` and recorded
as `RESUME_REJECTED` with the reason `nonce_binding`; the nonce is not spent.
A request that was presented and refused is not accepted when it is
presented again.

A request is verified before anything that depends on the state of the
session is answered: the key and the signature, the revocation of the key,
the binding of the nonce, the nonce, the prefix. Only a request that passed
them is told `resume_in_progress`, `already_attached` (a re-attach on an
attached session) or `not_attached` (a join on a detached one), and it has
spent its nonce by then. A key-exhausted session answers a re-attach or a
join by the same rules (`bad_signature` or `revoked_key`), never as
`key_exhausted`. Refusals of a revoked key are of the class that is logged
only up to the bound of I11 (g). A request the transport flags as a replay is
refused as `transport_replay`, and has spent its nonce if it was authentic.
A sequence number is a non-negative integer; a request with another value is
malformed (`bad_canonical`) and is not logged. A client registration follows
the same order: an authorising key id the session does not register, and a
nonce not bound to the authorising key, are answered `bad_signature`; that
the key is not connected (`via_not_connected`) or that the new key id is
taken (`key_already_registered`) is said only to a request that verified,
which has spent its nonce.

A timer that expires in the very tick of a re-attach or join waits for the
request (`advance` with `tick: false` moves the clock without evaluating the
timers); one that expired earlier has ended the session, and the request
gets the uniform refusal `refused`.

Operator events (`revoke` with a signature, `operator_add_key`,
`operator_terminate`) verify the operator's signature first: without it the
answer is `operator_signature_invalid` whatever the session, the key or the
lifecycle. The timers that are due fire before the check. With it, a
terminated session answers `terminated` (also to `operator_terminate`), a
quarantined one refuses a key addition as `quarantined`, a key that is
already revoked is refused as `revoked_key`, and a revocation reason other
than `rotation` or `compromise` is malformed (`bad_canonical`). A revocation
of the key whose re-attach is being verified abandons the verification,
whichever its reason.

A scope is a set: the bridge records it without repetitions and sorted by
code point, at attach and at every narrowing, and takes the authority hash
over that form. A tool call submitted with a client attached and no
escalation pending is forwarded if its permission is absent or in the
current scope; otherwise it is refused with the reason `scope` and recorded
as `TOOL_CALL_REJECTED` with `direct: true` and the permission asked for. A
call that comes without a key gets the next key of the form `tc-NNNN` (four
digits, counting from the number of keys the session has used plus one) that
the session has not used. Completion is accepted once for a call that was
forwarded, at a drain or directly, and refused for any other call. An
approval expiry belongs to the calls queued under the escalation it ends; an
approval is valid strictly before `T_approve` has elapsed.

On the wire, a `challenge` request carries `key_id`; `verified` and `joined`
carry the replayed events as event objects, `narrowed` carries
`new_version`, and `queued` and `forwarded` carry the `key` of the call. A
`revoke` without a signature (absent or empty) and with `requested_by` is a
client's request: an unsigned op, which only records the request. In wire
mode the Python runner validates every response against
`../schemas/messages/`.

## Test-harness convention for operator signatures

The operator key is the one that signs scope grants (seed `07` repeated).
Each signature is `hex(Ed25519-sign(operator_seed, message))` over the
canonical JSON of:

* revocation: `["bc/v1/revoke", bridge_id, session_id, key_id, reason, seq, head]`;
* key addition: `["bc/v1/add-key", bridge_id, session_id, key_id, scheme, public_key_hex, seq, head]`;
* termination: `["bc/v1/terminate", bridge_id, session_id, reason, seq, head]`.

`bridge_id` is the identity of the bridge under test; `seq` and `head` are the
sequence number and the event hash of the last committed event of the session
when the operator signs, which is the log as the action finds it. An operator
action takes `sig`: `ok` (default), `none` (no signature), `forged` (the same
bytes signed by another key, seed `09` repeated), `other-operation` (the
operator's signature over a different operation), `other-bridge` (bound to
another bridge id) or `stale` (bound to the position of the first event
instead of the head). Any value but `ok` must be refused as
`operator_signature_invalid`, commit nothing and leave the cell unchanged.
`bytes_kat.json` pins the bytes and the signatures (`operator_proofs`,
`operator_negatives`).

## Actions

Clients are named by key id; `ck-1` is the key registered at attach. A client
"observes" every event committed while it is connected, and again when `sync`
or `disconnect` names it; its next request acknowledges that last event.

| `do` | fields | calls |
|---|---|---|
| `disconnect` | `client?` | transport lost for one client, or for every connected client |
| `sync` | `client` | the client has observed every event so far |
| `escalate` | | agent escalates to a human |
| `resolve` | `answer?` (`all` default, or `none`) | answer every unanswered queued call with the hash the bridge recorded (a faithful client), then human resolves |
| `answer` | `key`, `hash?` (`shown` default; `content-only`, the hash of the action's `content` alone; or `other`), `content?`, `approve?` | human decision on a queued call |
| `tool_call` | `key?`, `tool`, `permission?`, `content?` | tool call submitted; the approval hash covers the tool, the permission and `content` (null when absent), and the forwarded request is exactly those (`forwarded_calls`); without `key` the bridge generates one; a duplicate key and a full queue are not refusals of the action (the wire answers `duplicate_key` and `queue_full`), a direct call outside the scope is (`error: true`, reason `scope`) |
| `narrow` | `scope` | propose a scope (narrowing; a widening is rejected) |
| `extend` | `scope`, `source?` (`requested` default, or `observed`) | propose a scope (a widening is rejected, or with `observed` reported and a revert requested; a subset is a no-op) |
| `add_client` | `client`, `via?`, `nonce?`, `proof?`, `reason?` | a connected client registers a further key, signing `["bc/v1/add-client", sid, via, new_key_id, scheme, public_key_hex, nonce]` with a nonce issued for `via` (or the nonce kept under the name `nonce`); `proof` is `valid` (default), `none` (empty signature), `forged` (another holder of the key id), `other-operation` (a join signature) or `replay` (the previous request again); a refusal (`error: true`) names its `reason`: `bad_signature`, `nonce_used`, ... A client that made a request before it was registered keeps the key it signed with |
| `revoke` | `client`, `reason?` (`rotation` default, or `compromise`), `requested_by?`, `signed?` (default true), `sig?` | the operator revokes a registered key; with `signed: false` and `requested_by` only the request is recorded |
| `operator_add_key` | `client`, `sig?` | the operator adds a key (of the vector's scheme) to a key-exhausted session; a client that made a request before it was registered keeps the key it signed with |
| `operator_terminate` | `sig?` | the operator terminates a key-exhausted session |
| `challenge` | `client?`, `as?` | request a nonce for the key id `client` (default: the key registered at attach; it need not be registered), and keep it under a name when `as` is given; refused (`error: true`) when the session already holds its maximum of live nonces (I11f) |
| `reattach` | `client?`, `nonce?`, `as?`, `replay_of?`, `prefix?`, `proof?`, `transport_replay?`, `complete?` | begin a re-attach; unless `complete: false`, complete it when the cell is Res |
| `join` | same as `reattach` | a further client joins an attached session |
| `complete_resume` | | finish verification (Res to Att) |
| `advance` | `seconds`, `tick?` | advance the clock, then evaluate timers; with `tick: false` the clock moves and no timer is evaluated, so the next request finds the timers as they stand at its own tick |
| `tick` | | evaluate timers |
| `restart` | `downtime?` | crash the process, let `downtime` seconds pass with no timer evaluated, recover from the durable log |
| `tamper_log` | `index`, `field: "prev_hash"` | corrupt the stored event at `index` |
| `plant_malformed_log` | `session_id`, `how: "no-genesis" or "missing-field"` | store, under another session id, a log that cannot be replayed |
| `other_quarantined` | `session_id` | assert that session is quarantined |
| `terminate` | | end the session (unsigned; refused on a key-exhausted session, which only `operator_terminate` ends) |
| `reattach_key_uniform` | `client` | assert that a re-attach naming the unregistered key `client` and one with an invalid signature are refused with the same text |
| `delivered` | `key` | the runtime acknowledges receipt of a forwarded call |
| `completed` | `key`, `result_hash?` | the runtime reports that a call finished |

Common optional fields on any action: `error: true` (the action MUST be
refused; default is that it MUST succeed), `then_cell` (assert the cell
after the action), `wire_reason` (the reason name the refusal carries on
the wire, which is the answer the caller gets; a runner that calls a bridge
directly checks it where its bridge reports a typed reason) and `log_reason`
(the `reason` field of the last committed event after the action, which may
differ from the answer: an unregistered key is answered `bad_signature` and
recorded as `unknown_key`).

`reattach` / `join` fields: `nonce` is `fresh` (default: request a challenge
for the requesting key id first), `unknown` (a nonce the bridge never
issued), or the name of a nonce kept by `challenge` or by an earlier
request's `as`. `as` keeps the request as well as its nonce, and
`replay_of: <name>` presents that request again, byte for byte, in place of
building a new one. `prefix` is `seen`
(default: the last event the client observed), `tip`, `hash-mismatch` (right
sequence, wrong hash), or `beyond` (a sequence the chain has not reached).
`proof` is `valid` (default), `invalid` (any other string), `wrong-key` (a real signature by another key of the same scheme, under the registered key id) `other-message` (a real signature by the registered key over the tuple with the sequence number advanced by one), `other-operation` (a real signature by the registered key made for the other operation: a join signature presented as a re-attach, or the reverse), `untagged` (the tuple without the domain tag) or `no-key-id` (the tagged tuple without the key id). A `client` that was never
registered signs with a key of its own.

## Test-harness convention for proof of possession

Not part of the contract (the paper only requires a signature under a
registered client key). The reference runners use Ed25519 or ECDSA P-256 (the vector's `scheme`), so the
bridge registry holds a scheme tag and public keys only:

* client key: an Ed25519 key pair; the raw 32-byte public key is registered at
  attach (or by `add_client`) under the client's key id, the seed stays with
  the client;
* the signed message is the RFC 8785 canonical JSON of the array
  `["bc/v1/reattach" | "bc/v1/join", session_id, key_id, nonce, seq, hash]`
  (Appendix B, signature scope); the bridge verifies against the operation
  it received, so a re-attach and a join sign different bytes;
* valid signature: `hex(Ed25519-sign(client_seed, message))`.

* `ecdsa-p256`: the registered key is the 65-byte SEC1 uncompressed point
  (the WebCrypto raw export); the signature is `hex(r || s)`, 64 bytes, over
  SHA-256 of the same message. A verifier accepts either form of `s`.

An `invalid` proof is any other string. `p256_kat.json` holds fixed
known-answer signatures made by the OpenSSL command line; both runners read
it. It is a scheme-level known answer: its message text is an arbitrary
byte string, not the domain-tagged tuple above, and it checks only that the
ECDSA P-256 verification (key encoding, `r || s` form, either form of `s`)
agrees across implementations. The bytes a bridge signs are pinned by
`bytes_kat.json`. `bytes_kat.json` pins the bytes: RFC 8785 canonical forms (non-ASCII
strings, escapes, UTF-16 key order, numbers) and inputs with no canonical
form, the canonical bytes and hash of an event and of tool-call content,
and the exact signed bytes and Ed25519 signature of re-attach and join
proofs, of an attach proof of possession and of a client registration under a
fixed seed, with signatures that must not verify. It also pins the bytes of
a challenge request (which names the key id), the authority hash over a
scope in canonical form, and the Merkle tree hash a `CHECKPOINT` carries:
the tree hash of RFC 9162, Section 2.1.1, over the event hashes (a leaf is
`SHA-256(0x00 || event_hash)`, an interior node `SHA-256(0x01 || left ||
right)`, a tree of more than one leaf is split at the largest power of two
smaller than its size, the empty tree hashes the empty string), with roots
for trees of event hashes and for the test tree of the Certificate
Transparency implementations, and audit paths for single leaves. Both
runners read it, and a third implementation can use it as a byte-level
conformance test without running a bridge.
