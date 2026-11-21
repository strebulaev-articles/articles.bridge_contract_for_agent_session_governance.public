# Event schemas

JSON Schemas (draft 2020-12 vocabulary; the keywords used are also valid in draft 7) for the governance events.

| File | What |
|---|---|
| `event.schema.json` | Envelope: `kind`, `session_id`, `sequence`, `prev_hash`, `payload`, `timestamp`; dispatches on `kind` to the payload schema |
| `events/<KIND>.schema.json` | Payload of one event kind; `x-invariants` names the invariants it serves |
| `build_schemas.py` | The single source; regenerates the files above |

`../check_schemas.py` runs the reference suite and validates every emitted event against these schemas. It fails when an emitted kind has no schema or a payload does not conform.

Notes:
- The `$id` base is a placeholder (`example.org`) until a stable home exists.
- Enumerated `reason` fields are closed where the specification fixes the codes (`RESUME_REJECTED`, `TOOL_CALL_REJECTED`, `TOOL_CALL_EXPIRED`) and open where the text is free-form (`TERMINATION`, `RECOVERY_FAILED`).
- `CHECKPOINT` is not emitted by the reference bridge (I-CHECKPOINT is SHOULD); its schema is provisional.
- The Rust crate shares the envelope; its payloads are checked by event kind through the vectors, not yet by these schemas.
