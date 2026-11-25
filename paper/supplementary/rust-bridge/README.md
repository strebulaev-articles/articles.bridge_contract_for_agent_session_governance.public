# bridge-contract (Rust)

A second implementation of the Bridge Contract: the product
state machine `Attachment x Human x Lifecycle` derived from a client set
(I15), challenge-response resume pinned to the acknowledged prefix of the
chain (I4, I9, I11), narrow-only authority with enforced and observed
changes (I3, I10), durable append (I12), restart recovery by log replay,
the tool queue (I13) and answer binding (I14).

It is a standalone crate with no dependency on Termenbox. The author reports
that a Termenbox integration vendors it; that product is closed source and
the report cannot be checked from this deposit.

```
cargo test        # runs ../vectors/*.json on two storages, plus unit tests
```

## API for a consumer

| Piece | What it is |
|---|---|
| `Storage` (trait, `Send + Sync`, `&self`) | `append_batch` (atomic, durable on return), `read_log`, `sessions`, and the client-key registry, scoped to a session (`register_key(sid, key_id, scheme, material)` refuses a key id already registered in that session; `unregister_key`, `key_record(sid, key_id)`, `key_ids(sid)`). Recovery rebuilds the registry from the scheme tag and public key in `ATTACHED`, `CLIENT_ADDED` and `OPERATOR_ADD_KEY`, and repairs a stored registry that is missing a key, holds one the log does not record, or differs from the log (`BRIDGE_RECOVERED` names the key ids repaired; only a chain that does not verify or malformed key material in the log quarantines the session). `MemStorage` is the reference implementation; the tests also run a file-backed one (`tests/common/mod.rs`: JSON lines, `fsync` per batch, a sync of the directory when a log file is created or the registry is replaced, a trailing record that is not fully durable discarded on read, and a fresh directory per run that is removed on every exit). |
| `Verifier` (trait, `Send + Sync`) | Proof-of-possession check over `(key material, message, signature)`. The registry records a scheme tag (`ed25519`, `ecdsa-p256`) with each key and the verifier receives it. `SchemeVerifier` dispatches to `Ed25519Verifier` (raw 32-byte key) and `EcdsaP256Verifier` (65-byte SEC1 uncompressed point, 64-byte `r || s` signature, SHA-256) and is the default used by the tests and vectors; the registry holds public keys as the key material and never a signing seed. A consumer may plug in another scheme. The signed message is `resume_message(op, sid, key_id, nonce, seq, hash)`, the RFC 8785 canonical JSON of `[tag, sid, key_id, nonce, seq, hash]` with the tag `bc/v1/reattach` or `bc/v1/join` (`ResumeOp`); `begin_resume` verifies as a re-attach, `join` as a join. |
| `Clock` (trait, `Send + Sync`) | `SystemClock` for production, `FakeClock` for tests. |
| `Config` | `T_call <= T_human` and `T_detach <= T_total` are checked by `Config::new`, `Bridge::new` and the profiles `Config::interactive_short()` and `Config::persistent()`. |
| `ClientPublicKey` | What a server receives of a client key: key id, scheme tag and public key (`ClientKey::public()`). `Bridge::attach` and `Bridge::operator_add_key` take this type, never a `ClientKey`, so the server cannot hold a signing key. |
| Attach | `Bridge::attach(identity, key, grant, proof)`. The grant (`grant_message(bridge_id, identity, key)`, tag `bc/v1/grant`) binds the bridge, session, principal, scope, lineage and the key (id, scheme, public key); the proof is the key's signature over `attach_message` (tag `bc/v1/attach`, same fields), made with `ClientKey::prove_attach`. Reasons: `grant_invalid`, `possession_invalid`. `Bridge::with_bridge_id` sets the bridge identity (default `DEFAULT_BRIDGE_ID`); a `GrantVerifier` receives it. |
| Key lifecycle (I11-REVOKE) | `Bridge::revoke_key` (soft `rotation`, hard `compromise`; a request without the operator signature records `KEY_REVOCATION_REQUESTED` only), `operator_add_key` and `operator_terminate` (the exits from `key_exhausted`; the unsigned `Bridge::terminate` is refused on such a session, but still ends a quarantined one), `revoked_keys`, `is_key_exhausted`. The operator signature is verified by the deployment's grant verifier (`GrantVerifier::verify_operation`); without a verifier, or with a signature that does not verify, the operation is refused and nothing is committed. Unsigned revocation requests are bounded per session (`REVOCATION_REQUEST_LIMIT`). A key id once registered is never accepted again by `operator_add_key`. |
| Wire front-end | `wire_server::WireServer::handle(&mut bridge, bytes)` mirrors `../wire_server.py`: it refuses bytes that are not canonical JSON (`bad_canonical`), serves `attach`, `challenge`, `add_client`, `reattach`, `join`, `disconnect`, `escalate`, `resolve`, `submit_tool_call`, `answer_tool_call`, `delivered`, `completed`, `narrow`, `extend` and `terminate`, and the operator events `revoke`, `add_key` and `operator_terminate` (verified against the operator key, not asked of the hook), names the reason of a refusal, and refuses any other op as `unsupported_op`. A `challenge` names the key id the nonce is for and is answered the same way for every key id; a request nested deeper than `MAX_DEPTH` is `bad_canonical` before it is parsed. `WireServer::with_authenticate(hook)` installs the transport's caller check, asked for the unsigned ops, and for a `revoke` that carries no operator signature (a client's request), before the bridge sees them (refusal: `unauthenticated`). `wire_server::send` returns the decoded response or the rejection reason. |
| `Bridge` | `Send`. Methods take `&mut self`; share one across threads as `Arc<Mutex<Bridge>>` (the tests do), or one bridge per session. |

The bridge keeps nothing a restart cannot rebuild from the `Storage`, except
the challenge nonces, which are volatile by design (I11b).

## Configuration beyond the timers

`Config::with_detached_calls(policy, allow)` selects what a call that arrives
with no escalation pending while no client is attached gets (G1): `Refuse`
(default), `Queue` (held until answered after re-attach) or `Forward` (an
allowlisted, in-scope call is forwarded at once). `Bridge::delivered` and
`Bridge::completed` record the runtime's acknowledgement; a drained call that
was not delivered is forwarded again by a bridge instance that has not yet
forwarded it, when the session is back in `(Att, None)`.

## What it checks

`tests/vectors.rs` consumes the same `../vectors/V*.json` that
`../run_vectors.py` runs against the Python bridge, once through `MemStorage`
and once through the file-backed storage. The vectors compare committed event
kinds, the final cell, the scope version, the queue, the forwarded calls, the
client set, the quarantine flag and the number of revert requests. Every vector passes on both storages.
`all_vectors_pass_through_the_wire_server` runs them again with the actions the front-end serves sent as Appendix B messages carrying real signatures (the Rust counterpart of `run_vectors.py --wire`), and `tests/wire_server.rs` checks the envelope, the reasons and the authentication hook.
Further tests check that `Bridge`, the storages, the clocks and the verifier
are `Send` (and `Sync`), and that a bridge shared behind a mutex serves
sessions from several threads. As a sanity check, deliberately breaking the
prefix check or the answer-hash comparison makes the vectors fail (V02, V25).

## Independence caveats

* Both implementations have the same author (and were produced in the same
  working session, after the Python bridge). The crate was written from the
  paper's Sections 4 and 5 and the vector schema, not by translating
  `conformance_suite.py`, but the author's reading of the specification is
  shared. Agreement between the two shows consistency of one reading, not
  independent confirmation of the specification. This holds for the
  changes that came from the Termenbox integration as much as for the
  rest: the same author wrote the product plan and the specification change.
* The architecture is the same: the cell is a fold of the committed log and a
  transition is an atomic append followed by an in-memory apply. That is a
  design choice of the specification's I7/I12, not an accident.
* Several choices are not forced by the paper text and were fixed by the
  vectors: the order of the request checks (transport replay, registered key,
  signature, nonce, prefix), the `RESUME_REJECTED` reasons, and the event
  order inside a batch. A third implementation could differ on these and
  still be conformant; if so, the vectors, not this crate, are the arbiter.
* Proof of possession uses Ed25519 (`ed25519-dalek`) or ECDSA P-256
  (`p256`); the registry holds a scheme tag and public keys only. The
  `Verifier` trait is the seam for other schemes, and only these two have
  been exercised. The P-256 verifier accepts either form of `s`, since
  WebCrypto does not normalise it. Unforgeability is assumed, not proved.
* The file-backed storage is a test fixture: no cross-process locking, no
  compaction, and `read_log` reads the whole file. A production `Storage`
  needs its own answer to those.
* The hash-chain encodings are RFC 8785 canonical JSON, pinned by
  `../vectors/bytes_kat.json`, which this crate and the Python bridge both
  read; the vectors still compare event kinds, not hashes.
* Not implemented: I-CHECKPOINT (SHOULD), I-SIGN-EVENT (SHOULD), I8's source
  of truth (the transport reports a replay through a flag), and the bridge's
  rate limiting of challenges and rejections (a SHOULD of I11).
