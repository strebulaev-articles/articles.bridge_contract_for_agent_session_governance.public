#!/usr/bin/env python3
"""Generate wire-format JSON schemas for the client--bridge messages.

Creates:
- schemas/message.schema.json  (envelope, allOf conditionals)
- schemas/messages/<op>.schema.json  (one per op-type)

Run from paper/supplementary/:
    python3 schemas/build_wire_schemas.py
"""
import json
from pathlib import Path

SCHEMA_DIR = Path(__file__).resolve().parent
MSG_DIR = SCHEMA_DIR / "messages"
MSG_DIR.mkdir(exist_ok=True)

OPS = {
    "attach": {
        "request": {
            "session_id": {"type": "string"},
            "principal": {"type": "string"},
            "scope": {"type": "array", "items": {"type": "string"}},
            "lineage": {"type": "array", "items": {"type": "string"}},
            "key_id": {"type": "string"},
            "scheme": {"type": "string",
                       "description": "Signature scheme tag of the client key (ed25519, ecdsa-p256)."},
            "public_key": {"type": "string", "pattern": "^[0-9a-f]+$",
                           "description": "Client public key, hex-encoded; its encoding is fixed by the scheme."},
            "grant": {"type": "string", "minLength": 1,
                      "description": "Opaque scope grant, presented to the deployment's grant verifier; it binds the session, principal, scope, lineage and client key. Not covered by the client signature. The reference verifier takes a hex Ed25519 operator signature over the domain tag bc/v1/grant and those fields."},
            "signature": {"type": "string", "pattern": "^[0-9a-f]+$",
                          "description": "Signature by the attaching key over canonical JSON of [\"bc/v1/attach\", bridge_id, session_id, principal, scope, lineage, key_id, scheme, public_key]."},
        },
        "request_required": [" " " ".join("session_id principal scope lineage key_id scheme public_key grant signature".split())],
        "response_status": "attached",
        "response": {
            "seq": {"type": "integer", "minimum": 0, "const": 0,
                    "description": "Genesis sequence number."},
            "hash": {"type": "string", "pattern": "^[0-9a-f]{64}$",
                     "description": "Hash of the genesis ATTACHED event."},
        },
        "response_required": ["seq", "hash"],
    },
    "add_client": {
        "request": {
            "session_id": {"type": "string"},
            "via_key_id": {"type": "string"},
            "new_key_id": {"type": "string"},
            "scheme": {"type": "string"},
            "new_public_key": {"type": "string", "pattern": "^[0-9a-f]+$"},
            "nonce": {"type": "string", "description": "Challenge nonce, single use."},
            "signature": {"type": "string", "pattern": "^[0-9a-f]+$",
                          "description": "Signature by via_key_id over canonical JSON of [\"bc/v1/add-client\", session_id, via_key_id, new_key_id, scheme, new_public_key, nonce]."},
        },
        "request_required": ["session_id", "via_key_id", "new_key_id", "scheme", "new_public_key", "nonce", "signature"],
        "response_status": "added",
        "response": {},
        "response_required": [],
    },
    "challenge": {
        "request": {
            "session_id": {"type": "string"},
        },
        "request_required": ["session_id"],
        "response_status": "nonce",
        "response": {
            "nonce": {"type": "string", "pattern": "^[0-9a-f]{32,}$",
                      "description": "Fresh single-use nonce (>= 128 bits)."},
            "ttl_seconds": {"type": "number", "minimum": 0},
        },
        "response_required": ["nonce", "ttl_seconds"],
    },
    "reattach": {
        "request": {
            "session_id": {"type": "string"},
            "key_id": {"type": "string"},
            "nonce": {"type": "string"},
            "seq": {"type": "integer", "minimum": 0},
            "hash": {"type": "string"},
            "signature": {"type": "string", "pattern": "^[0-9a-f]+$",
                          "description": "Ed25519 signature over canonical JSON of [session_id, nonce, seq, hash]."},
        },
        "request_required": ["session_id", "key_id", "nonce", "seq", "hash", "signature"],
        "response_status": "verified",
        "response": {
            "events": {"type": "array", "items": {"type": "object"},
                       "description": "Committed events after seq, replayed to the client."},
        },
        "response_required": ["events"],
    },
    "join": {
        "request": {
            "session_id": {"type": "string"},
            "key_id": {"type": "string"},
            "nonce": {"type": "string"},
            "seq": {"type": "integer", "minimum": 0},
            "hash": {"type": "string"},
            "signature": {"type": "string", "pattern": "^[0-9a-f]+$"},
        },
        "request_required": ["session_id", "key_id", "nonce", "seq", "hash", "signature"],
        "response_status": "joined",
        "response": {
            "events": {"type": "array", "items": {"type": "object"}},
        },
        "response_required": ["events"],
    },
    "disconnect": {
        "request": {
            "session_id": {"type": "string"},
            "key_id": {"type": "string",
                       "description": "Optional; absent means all connected clients."},
            "reason": {"type": "string"},
        },
        "request_required": ["session_id", "reason"],
        "response_status": "disconnected",
        "response": {},
        "response_required": [],
    },
    "escalate": {
        "request": {
            "session_id": {"type": "string"},
            "trigger": {"type": "string",
                        "description": "Optional trigger description."},
        },
        "request_required": ["session_id"],
        "response_status": "escalated",
        "response": {},
        "response_required": [],
    },
    "resolve": {
        "request": {
            "session_id": {"type": "string"},
        },
        "request_required": ["session_id"],
        "response_status": "resolved",
        "response": {},
        "response_required": [],
    },
    "submit_tool_call": {
        "request": {
            "session_id": {"type": "string"},
            "tool": {"type": "string"},
            "key": {"type": "string",
                    "description": "Idempotency key; optional (bridge generates if absent)."},
            "permission": {"type": "string"},
            "content": {"type": "object",
                        "description": "What the human is shown; the bridge hashes this for I14."},
        },
        "request_required": ["session_id", "tool", "content"],
        "response_statuses": ["queued", "forwarded"],
        "response": {
            "key": {"type": "string",
                    "description": "The idempotency key (echoed or generated)."},
        },
        "response_required": ["key"],
    },
    "answer_tool_call": {
        "request": {
            "session_id": {"type": "string"},
            "key": {"type": "string"},
            "shown_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$",
                           "description": "h_a: hash of the content the client displayed."},
            "decision": {"type": "string", "enum": ["approve", "deny"]},
        },
        "request_required": ["session_id", "key", "shown_hash", "decision"],
        "response_status": "answered",
        "response": {},
        "response_required": [],
    },
    "delivered": {
        "request": {
            "session_id": {"type": "string"},
            "key": {"type": "string"},
        },
        "request_required": ["session_id", "key"],
        "response_status": "delivered",
        "response": {},
        "response_required": [],
    },
    "completed": {
        "request": {
            "session_id": {"type": "string"},
            "key": {"type": "string"},
            "result_hash": {"type": "string"},
        },
        "request_required": ["session_id", "key"],
        "response_status": "completed",
        "response": {},
        "response_required": [],
    },
    "narrow": {
        "request": {
            "session_id": {"type": "string"},
            "new_scope": {"type": "array", "items": {"type": "string"}},
        },
        "request_required": ["session_id", "new_scope"],
        "response_status": "narrowed",
        "response": {
            "new_version": {"type": "integer", "minimum": 1},
        },
        "response_required": ["new_version"],
    },
    "extend": {
        "request": {
            "session_id": {"type": "string"},
            "new_scope": {"type": "array", "items": {"type": "string"}},
            "source": {"type": "string", "enum": ["requested", "observed"]},
        },
        "request_required": ["session_id", "new_scope", "source"],
        "response_status": "rejected",
        "response_statuses": ["rejected", "revert_requested", "unchanged"],
        "response": {
            "reason": {"const": "extension_rejected",
                       "description": "Present with status rejected: a widening asked for through the bridge (I3)."},
            "current_scope": {"type": "array", "items": {"type": "string"}},
        },
        "response_required": ["current_scope"],
    },
    "revoke": {
        "request": {
            "session_id": {"type": "string"},
            "key_id": {"type": "string"},
            "reason": {"type": "string", "enum": ["rotation", "compromise"]},
            "signature": {"type": "string", "pattern": "^[0-9a-f]*$",
                          "description": "Operator signature over canonical JSON of [\"bc/v1/revoke\", bridge_id, session_id, key_id, reason, seq, head]; empty with requested_by records only a request."},
            "requested_by": {"type": "string"},
        },
        "request_required": ["session_id", "key_id", "reason"],
        "response_status": "revoked",
        "response_statuses": ["revoked", "requested"],
        "response": {},
        "response_required": [],
    },
    "add_key": {
        "request": {
            "session_id": {"type": "string"},
            "key_id": {"type": "string"},
            "scheme": {"type": "string"},
            "public_key": {"type": "string", "pattern": "^[0-9a-f]+$"},
            "signature": {"type": "string", "pattern": "^[0-9a-f]+$",
                          "description": "Operator signature over canonical JSON of [\"bc/v1/add-key\", bridge_id, session_id, key_id, scheme, public_key, seq, head]."},
        },
        "request_required": ["session_id", "key_id", "scheme", "public_key"],
        "response_status": "key_added",
        "response": {},
        "response_required": [],
    },
    "operator_terminate": {
        "request": {
            "session_id": {"type": "string"},
            "reason": {"type": "string"},
            "signature": {"type": "string", "pattern": "^[0-9a-f]+$",
                          "description": "Operator signature over canonical JSON of [\"bc/v1/terminate\", bridge_id, session_id, reason, seq, head]."},
        },
        "request_required": ["session_id", "reason"],
        "response_status": "terminated",
        "response": {},
        "response_required": [],
    },
    "terminate": {
        "request": {
            "session_id": {"type": "string"},
            "reason": {"type": "string"},
        },
        "request_required": ["session_id", "reason"],
        "response_status": "terminated",
        "response": {},
        "response_required": [],
    },
    "tick": {
        "request": {
            "session_id": {"type": "string",
                           "description": "Optional; absent means all sessions."},
        },
        "request_required": [],
        "response_status": "ticked",
        "response": {},
        "response_required": [],
    },
    "restart": {
        "request": {},
        "request_required": [],
        "response_status": "restarted",
        "response": {},
        "response_required": [],
    },
}

# Fix the attach request_required (workaround for f-string in dict above)
OPS["attach"]["request_required"] = ["session_id", "principal", "scope", "lineage", "key_id", "scheme", "public_key", "grant", "signature"]

REASONS = [
    "unknown_session", "unknown_key", "nonce_used", "nonce_expired", "nonce_unknown",
    "prefix_mismatch", "resume_in_progress", "already_attached", "transport_replay",
    "queue_full", "unanswered", "denied", "answer_mismatch", "scope",
    "call_ttl", "approval_ttl", "terminated", "quarantined",
    "not_a_strict_narrowing", "bad_signature", "bad_canonical",
    "revoked_key", "key_exhausted", "duplicate_key", "grant_invalid",
    "unauthenticated", "possession_invalid", "operator_signature_invalid",
    "not_key_exhausted", "key_already_registered", "extension_rejected",
    "via_not_connected", "unsupported_op", "refused",
]


def make_op_schema(op_name: str, spec: dict) -> dict:
    """Per-op schema: request fields + response fields + error."""
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://example.org/bridge-contract/schemas/messages/{op_name}.schema.json",
        "title": f"Wire op: {op_name}",
        "type": "object",
        "properties": {
            "op": {"const": op_name},
            "session_id": {"type": "string"},
            **spec["request"],
        },
        "required": ["op"] + spec["request_required"],
        "additionalProperties": False,
    }


def make_response_schema(op_name: str, spec: dict) -> dict:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://example.org/bridge-contract/schemas/messages/{op_name}.response.schema.json",
        "title": f"Wire response: {op_name}",
        "type": "object",
        "properties": {
            "status": ({"enum": spec["response_statuses"]}
                       if "response_statuses" in spec
                       else {"const": spec["response_status"]}),
            "session_id": {"type": "string"},
            **spec["response"],
        },
        "required": ["status", "session_id"] + spec["response_required"],
        "additionalProperties": False,
    }


def make_error_schema() -> dict:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://example.org/bridge-contract/schemas/messages/error.schema.json",
        "title": "Wire error response",
        "type": "object",
        "properties": {
            "status": {"const": "rejected"},
            "session_id": {"type": "string"},
            "reason": {"enum": REASONS},
        },
        "required": ["status", "session_id", "reason"],
        "additionalProperties": False,
    }


def make_envelope_schema() -> dict:
    """The envelope schema with allOf conditionals for each op-type."""
    cond = []
    for op_name, spec in OPS.items():
        cond.append({
            "if": {
                "properties": {"op": {"const": op_name}},
                "required": ["op"],
            },
            "then": {
                "properties": {
                    f: {} for f in spec["request"]
                },
                "required": spec["request_required"],
            },
        })
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://example.org/bridge-contract/schemas/message.schema.json",
        "title": "Bridge Contract client-bridge wire message (envelope)",
        "description": (
            "Envelope for all client->bridge requests. The `op` field "
            "selects the op-type; the op-specific fields are validated "
            "by the per-op schemas in messages/<op>.schema.json. "
            "Responses use `status` instead of `op`; see "
            "messages/<op>.response.schema.json and messages/error.schema.json."
        ),
        "type": "object",
        "properties": {
            "op": {
                "enum": list(OPS.keys()),
                "description": "The op-type; selects the op-specific fields.",
            },
            "session_id": {
                "type": "string",
                "description": (
                    "The session the request targets. Absent only for "
                    "`restart` (bridge-level) and `tick` without a session "
                    "(all sessions)."
                ),
            },
        },
        "required": ["op"],
        "additionalProperties": True,
        "allOf": cond,
    }


def main():
    # Envelope
    (SCHEMA_DIR / "message.schema.json").write_text(
        json.dumps(make_envelope_schema(), indent=2) + "\n")
    # Per-op request + response
    for op_name, spec in OPS.items():
        (MSG_DIR / f"{op_name}.schema.json").write_text(
            json.dumps(make_op_schema(op_name, spec), indent=2) + "\n")
        (MSG_DIR / f"{op_name}.response.schema.json").write_text(
            json.dumps(make_response_schema(op_name, spec), indent=2) + "\n")
    # Error
    (MSG_DIR / "error.schema.json").write_text(
        json.dumps(make_error_schema(), indent=2) + "\n")
    print(f"Wrote message.schema.json, error.schema.json, and "
          f"{len(OPS)} * 2 = {len(OPS) * 2} per-op schemas to {MSG_DIR}")


if __name__ == "__main__":
    main()
