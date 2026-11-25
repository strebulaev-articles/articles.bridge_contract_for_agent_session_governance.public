# Event schemas

JSON Schemas (draft 2020-12 vocabulary; the keywords used are also valid in draft 7) for the governance events.

| File | What |
|---|---|
| `event.schema.json` | Envelope: `kind`, `session_id`, `sequence`, `prev_hash`, `payload`, `timestamp`; dispatches on `kind` to the payload schema |
| `events/<KIND>.schema.json` | Payload of one event kind; `x-invariants` names the invariants it serves |
| `build_schemas.py` | The single source; regenerates the files above |
| `message.schema.json` | Envelope of a client request: `op` and the fields each op requires |
| `messages/<op>.schema.json`, `messages/<op>.response.schema.json`, `messages/error.schema.json` | One request, its response, and the rejection with the closed list of wire reasons |
| `build_wire_schemas.py` | The single source of the message schemas |

`../check_schemas.py` runs the reference suite and validates every emitted event against these schemas. It fails when an emitted kind has no schema, when a payload does not conform, or when a schema is never exercised. `../run_vectors.py --wire` validates every response of the wire server against the response schema of its op, or the error schema for a rejection, and every event a `verified` or `joined` response carries against the event schemas.

Notes:
- The `$id` base is a placeholder (`example.org`) until a stable home exists.
- Enumerated `reason` fields are closed where the specification fixes the codes (`RESUME_REJECTED`, `TOOL_CALL_REJECTED`, `TOOL_CALL_EXPIRED`, `KEY_REVOKED`) and open where the text is free-form (`TERMINATION`, `RECOVERY_FAILED`).
- The reasons of `RESUME_REJECTED` are the ones the log keeps. `unknown_key` and `nonce_binding` are answered to the caller as `bad_signature`, so `nonce_binding` is not a wire reason.
- A `challenge` request names the key id the nonce is for (`key_id`, required); its response is the same for every key id.
- `CHECKPOINT` carries the tree size and the Merkle tree hash of RFC 9162, Section 2.1.1, over the event hashes (`../merkle.py`); the Python bridge emits it, the suite runs a test family with checkpoints on, and the signature field is a placeholder.
- The Rust crate shares the envelope; its payloads are checked by event kind through the vectors, not yet by these schemas.
