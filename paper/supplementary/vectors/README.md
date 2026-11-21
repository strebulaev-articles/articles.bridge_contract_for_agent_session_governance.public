# Language-neutral test vectors

One scenario per `Vnn.json`. A runner builds a bridge, creates the session
from `session`, applies `actions` in order, then checks `expect`.

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
| `tool_call` | `key`, `tool`, `permission?`, `content?` | tool call submitted; the approval hash covers the tool, the permission and `content` (null when absent), and the forwarded request is exactly those (`forwarded_calls`) |
| `narrow` | `scope` | propose a scope (narrowing; a widening is rejected) |
| `extend` | `scope`, `source?` (`requested` default, or `observed`) | propose a scope (a widening is rejected, or with `observed` reported and a revert requested; a subset is a no-op) |
| `add_client` | `client`, `via?`, `proof?`, `reason?` | a connected client registers a further key, signing `["bc/v1/add-client", sid, via, new_key_id, scheme, public_key_hex, nonce]` with a fresh nonce; `proof` is `valid` (default), `none` (empty signature), `forged` (another holder of the key id), `other-operation` (a join signature) or `replay` (the previous request again); a refusal (`error: true`) names its `reason`: `bad_signature`, `nonce_used`, ... |
| `revoke` | `client`, `reason?` (`rotation` default, or `compromise`), `requested_by?`, `signed?` (default true), `sig?` | the operator revokes a registered key; with `signed: false` and `requested_by` only the request is recorded |
| `operator_add_key` | `client`, `sig?` | the operator adds a key (of the vector's scheme) to a key-exhausted session |
| `operator_terminate` | `sig?` | the operator terminates a key-exhausted session |
| `challenge` | `as?` | request a nonce, and keep it under a name when `as` is given; refused (`error: true`) when the session already holds its maximum of live nonces (I11f) |
| `reattach` | `client?`, `nonce?`, `as?`, `prefix?`, `proof?`, `transport_replay?`, `complete?` | begin a re-attach; unless `complete: false`, complete it when the cell is Res |
| `join` | same as `reattach` | a further client joins an attached session |
| `complete_resume` | | finish verification (Res to Att) |
| `advance` | `seconds` | advance the clock, then evaluate timers |
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
after the action) and `wire_reason` (in wire mode only: the reason name the
refusal carries on the wire; ignored by a runner that calls the bridge
directly).

`reattach` / `join` fields: `nonce` is `fresh` (default: request a challenge
first), `unknown` (a nonce the bridge never issued), or the name of a nonce
kept by `challenge` or by an earlier request's `as`. `prefix` is `seen`
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
fixed seed, with signatures that must not verify. Both
runners read it, and a third implementation can use it as a byte-level
conformance test without running a bridge.
