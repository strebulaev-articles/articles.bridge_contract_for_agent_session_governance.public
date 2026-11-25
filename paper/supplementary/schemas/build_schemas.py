#!/usr/bin/env python3
"""Generate the JSON Schemas for the governance event kinds.

Writes schemas/event.schema.json (the envelope; dispatches on `kind`) and
schemas/events/<KIND>.schema.json (the payload of one kind).  The definitions
below are the single source; the generated files are committed so that
implementers need not run this script.  `check_schemas.py` validates every
event emitted by the reference suite against them.
"""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = "https://example.org/bridge-contract/schemas"  # placeholder id; see README

STR = {"type": "string"}
SCHEME = {"type": "string", "enum": ["ed25519", "ecdsa-p256"],
          "description": "Scheme tag of the registered public key."}
PUBKEY = {"type": "string", "pattern": "^([0-9a-f]{64}|[0-9a-f]{130})$",
          "description": "Hex public key: 32 bytes (ed25519) or a 65-byte SEC1 uncompressed point (ecdsa-p256)."}
INT = {"type": "integer", "minimum": 0}
NUM = {"type": "number"}
HEX = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
DIGEST = {"type": "string", "pattern": "^[0-9a-f]{16,64}$", "description": "Hex digest, truncated to at least 64 bits."}
SCOPE = {"type": "array", "items": STR, "uniqueItems": True}
CELLS = ["Att/None", "Att/Pend", "Det/None", "Det/Pend", "Res/None", "Res/Pend"]


def obj(props, required=None, doc=""):
    return {
        "description": doc,
        "type": "object",
        "properties": props,
        "required": list(props) if required is None else required,
        "additionalProperties": False,
    }


def reason(values=None, doc="Reason code."):
    return {"type": "string", "enum": values, "description": doc} if values else {"type": "string", "description": doc}


# kind -> (invariants, payload schema)
EVENTS = {
    "ATTACHED": ("I5, I11", obj({
        "principal_id": STR, "authority_scope": SCOPE,
        "task_lineage": {"type": "array", "items": STR},
        "client_key_id": STR, "scheme": SCHEME, "public_key": PUBKEY,
        "scope_version": {"const": 0}},
        doc="Genesis event; registers the first client key with its scheme tag and public key.")),
    "CLIENT_JOINED": ("I15", obj({
        "key_id": STR, "seq": INT, "hash": HEX, "nonce_digest": DIGEST},
        doc="An authentic request from a registered key while attached; carries the acknowledged (seq, hash).")),
    "CLIENT_LEFT": ("I15", obj({
        "key_id": STR, "reason": reason(["client_disconnect"])},
        doc="One client disconnected while others remain; the cell is unchanged.")),
    "CLIENT_ADDED": ("I15", obj({
        "key_id": STR, "via": {**STR, "description": "key_id of the connected client that authorised the addition"},
        "scheme": SCHEME, "public_key": PUBKEY},
        doc="A further client key registered for the principal, with its scheme tag and public key.")),
    "DETACHMENT": ("I1", obj({
        "reason": reason(["client_disconnect", "bridge_restart", "key_revoked"])},
        doc="Last connected client left, the bridge restarted, or a revocation removed the last connected key or the key whose re-attach was being verified.")),
    "RESUME_PREPARED": ("I1", obj({
        "authority_hash": STR, "reason": reason(["client_disconnect", "bridge_restart", "key_revoked"]),
        "authority_scope": SCOPE, "scope_version": INT,
        "pending_tool_calls": {"type": "array"}},
        doc="The bridge's own resume record; nothing is delivered to the client.")),
    "RESUME_STARTED": ("I4, I9, I11", obj({
        "key_id": STR, "seq": INT, "hash": HEX, "nonce_digest": DIGEST},
        doc="An authentic, fresh, prefix-pinned re-attach request; enters Res.")),
    "RESUME_REJECTED": ("I4, I8, I9, I11", obj({
        "key_id": STR, "seq": {"type": "integer", "minimum": 0, "description": "Client-claimed sequence number, as presented (it may lie beyond the log; a request with a negative one is malformed and is not logged)."},
        "reason": reason(["bad_signature", "nonce_expired", "nonce_unknown", "nonce_used",
                          "prefix_mismatch", "resume_in_progress", "already_attached",
                          "transport_replay", "unknown_key", "revoked_key",
                          "nonce_binding", "not_attached"],
                         doc="Reason code, as the log keeps it. unknown_key and nonce_binding (the nonce was issued for another key id, or for this key id while it was not an active key of the session) are answered to the caller as bad_signature.")},
        doc="A re-attach or join request refused; informational, the cell is unchanged.")),
    "RESUME_VERIFIED": ("I5", obj({}, doc="Chain verified during re-attach; returns to Att.")),
    "RESUME_FAILED": ("I5", obj({"reason": reason(["chain"])},
        doc="Chain verification failed during re-attach. The session is quarantined: its cell is unchanged, it accepts no client operation and no timer acts on it.")),
    "HUMAN_PENDING": ("I2", obj({"reason": reason(["human_unavailable", "tool_needs_confirmation"])},
        doc="The agent escalated to a human; sets the human dimension to Pend.")),
    "HUMAN_RESOLVED": ("I13", obj({"valid_until": NUM}, required=[],
        doc="Human resolution; valid_until bounds the approval validity (I13) when present.")),
    "HUMAN_TIMEOUT": ("L2", obj({"reason": reason(["human_timeout"])},
        doc="T_human expired.")),
    "DETACH_TIMEOUT": ("L1", obj({"reason": reason(["detach_timeout", "detach_total_timeout"])},
        doc="T_detach expired while detached, or the time spent detached over all episodes reached T_total.")),
    "AUTHORITY_EXTENSION_REJECTED": ("I3", obj({
        "proposed": SCOPE, "current": SCOPE, "cell": {"type": "string", "enum": CELLS},
        "source": {"type": "string", "enum": ["requested", "observed"]}},
        doc="An attempt to widen Authority-Scope, requested through the bridge or observed.")),
    "AUTHORITY_NARROWED": ("I10", obj({"new_scope": SCOPE, "new_version": {"type": "integer", "minimum": 1}},
        doc="Successful narrowing; new_version = previous_version + 1.")),
    "AUTHORITY_NARROWING_REJECTED": ("I10", obj({
        "proposed": SCOPE, "current": SCOPE, "reason": reason(doc="Why it was refused, e.g. 'not a strict narrowing'.")},
        doc="An out-of-order, duplicate or non-narrowing change attempt.")),
    "TERMINATION": ("I6", obj({"reason": reason(doc=(
        "Termination reason, e.g. human_timeout, detach_timeout, detach_total_timeout, "
        "'human_timeout+detach_timeout (simultaneous)', "
        "'human_timeout+detach_total_timeout (simultaneous)', user_quit."))},
        doc="Irreversible session end.")),
    "TOOL_CALL_QUEUED": ("I2, I13, I14", obj({
        "key": STR, "tool": STR, "permission": {"type": ["string", "null"]},
        "content": {"description": "The call's content as hashed and as forwarded (null when none was supplied); retained so that the forwarded request is the hashed one."},
        "shown_hash": HEX, "expires_at": NUM,
        "held": {"type": "boolean", "description": "True when queued with no escalation pending while no client was attached (detached_calls policy)."}},
        required=["key", "tool", "permission", "content", "shown_hash", "expires_at"],
        doc="A tool call queued while the human dimension is Pend, or held for an answer under the detached-call policy; shown_hash is h_q, the hash of the tool, the permission and the content.")),
    "TOOL_CALL_ANSWERED": ("I14", obj({
        "key": STR, "shown_hash": HEX, "decision": {"type": "string", "enum": ["approve", "deny"]},
        "source": {"type": "string", "enum": ["operator_policy"], "description": "Present when the operator's allowlist, not a human, approved the call."}},
        required=["key", "shown_hash", "decision"],
        doc="A decision on a queued call; shown_hash is h_a.")),
    "TOOL_CALL_DRAINED": ("I13", obj({
        "key": STR, "tool": STR, "permission": {"type": ["string", "null"]},
        "content": {"description": "The retained content, forwarded as hashed."},
        "authority_hash": STR, "shown_hash": HEX},
        doc="A queued call forwarded at drain with its retained tool, permission and content; repeats h_q.")),
    "TOOL_CALL_DELIVERED": ("I12, I13", obj({"key": STR},
        doc="The runtime acknowledged that it received a forwarded call; until then a restart forwards the call again with the same key.")),
    "TOOL_CALL_COMPLETED": ("I13", obj({"key": STR, "result_hash": {"type": "string"}}, required=["key"],
        doc="The runtime reported that a forwarded call finished.")),
    "TOOL_CALL_REJECTED": ("I3, I13, I14", obj({
        "key": STR, "tool": STR,
        "reason": reason(["queue_full", "scope", "unanswered", "denied", "answer_mismatch"]),
        "permission": {"type": "string", "description": "The permission the call asked for; present on a direct call refused for its scope, which has no TOOL_CALL_QUEUED event to carry it."},
        "direct": {"const": True, "description": "Present when the call was submitted with a client attached and no escalation pending and was refused without being queued (reason scope)."}},
        required=["key", "tool", "reason"],
        doc="A call refused at a full queue, refused on the direct path because its permission is outside the current scope, or dropped at drain.")),
    "TOOL_CALL_EXPIRED": ("I13", obj({
        "key": STR, "tool": STR, "reason": reason(["call_ttl", "approval_ttl"])},
        doc="A queued call outlived T_call, or its approval outlived T_approve.")),
    "BRIDGE_RECOVERED": ("I12", obj({
        "events": INT,
        "registry_repaired": {"type": "array", "items": STR, "description":
            "Key ids whose registry entry recovery repaired from the log: dropped, written back or replaced."}},
        required=["events"],
        doc="Session recovered after a bridge restart by log replay. The log is the source of truth for the key registry.")),
    "RECOVERY_FAILED": ("I12", obj({"reason": reason(doc="Free-form diagnostic.")},
        doc="Recovery failed. The session is quarantined: no TERMINATION is emitted, the cell is unchanged and an operator decides.")),
    "CHECKPOINT": ("I-CHECKPOINT (SHOULD)", obj({
        "root": {**HEX, "description": "Merkle tree hash (RFC 9162, Section 2.1.1) over the event hashes of the events 0..tree_size-1 of this session: a leaf is SHA-256(0x00 || event_hash), an interior node SHA-256(0x01 || left || right), a tree of more than one leaf is split at the largest power of two smaller than its size, and the hash of the empty tree is SHA-256 of the empty string."},
        "tree_size": {**INT, "description": "Number of events covered by this checkpoint (the tree has this many leaves); the CHECKPOINT event itself is the next one."},
        "signature": {**STR, "description": "Ed25519 signature under the operator key, over canonical JSON of [root, tree_size]. Hex-encoded. The reference bridge writes a placeholder."},
        "receipt": {**STR, "description": "Optional. Receipt from an external append-only transparency log (e.g., SCITT) that anchors this checkpoint."}},
        required=["root", "tree_size", "signature"],
        doc="Merkle tree hash over all preceding event hashes, with the tree size, the operator signature and an optional external receipt. Emitted periodically (every N events or T_cp) on an active, unquarantined session whose hash chain verifies.")),
    "KEY_REVOKED": ("I11-REVOKE", obj({
        "key_id": STR, "reason": {"type": "string", "enum": ["rotation", "compromise"]},
        "revoked_at": NUM,
        "signature": {**STR, "description": "Ed25519 operator signature over canonical JSON of [\"bc/v1/revoke\", bridge_id, session_id, key_id, reason, seq, head], where seq and head are the sequence number and hash of the last event when the operator signed."}},
        doc="Operator-signed revocation of a registered client key: rotation (soft) or compromise (hard).")),
    "KEY_REVOCATION_REQUESTED": ("I11-REVOKE", obj({
        "key_id": STR, "requested_by": STR,
        "reason": {"type": "string", "enum": ["rotation", "compromise"]}},
        doc="A client requested revocation; the operator must approve. Informational.")),
    "OPERATOR_ADD_KEY": ("I11-REVOKE", obj({
        "key_id": STR, "scheme": SCHEME, "public_key": PUBKEY,
        "signature": {**STR, "description": "Ed25519 operator signature over canonical JSON of [\"bc/v1/add-key\", bridge_id, session_id, key_id, scheme, public_key, seq, head]."}},
        doc="Operator adds a key to a key_exhausted session, clearing the predicate.")),
    "OPERATOR_TERMINATION": ("I11-REVOKE, I6", obj({
        "reason": STR,
        "signature": {**STR, "description": "Ed25519 operator signature over canonical JSON of [\"bc/v1/terminate\", bridge_id, session_id, reason, seq, head]."}},
        doc="Operator terminates a key_exhausted session.")),
}


def main() -> None:
    (HERE / "events").mkdir(exist_ok=True)
    refs = []
    for kind, (inv, payload) in EVENTS.items():
        doc = {"$schema": "https://json-schema.org/draft/2020-12/schema",
               "$id": f"{BASE}/events/{kind}.schema.json",
               "title": f"{kind} payload", "x-invariants": inv, **payload}
        (HERE / "events" / f"{kind}.schema.json").write_text(json.dumps(doc, indent=2) + "\n")
        refs.append({"if": {"properties": {"kind": {"const": kind}}, "required": ["kind"]},
                     "then": {"properties": {"payload": {"$ref": f"events/{kind}.schema.json"}}}})
    env = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"{BASE}/event.schema.json",
        "title": "Bridge Contract governance event",
        "description": "Envelope of one governance event. `prev_hash` is the SHA-256 of the canonical "
                       "JSON (RFC 8785) of the preceding event, empty for the genesis event (I5). The "
                       "event's own hash is derived, not a field.",
        "type": "object",
        "properties": {
            "kind": {"enum": list(EVENTS)},
            "session_id": STR,
            "sequence": {**INT, "description": "Monotonic per session, 0 at genesis."},
            "prev_hash": {"type": "string", "pattern": "^([0-9a-f]{64})?$"},
            "payload": {"type": "object"},
            "timestamp": {**NUM, "description": "Informational; never used for ordering."},
        },
        "required": ["kind", "session_id", "sequence", "prev_hash", "payload", "timestamp"],
        "additionalProperties": False,
        "allOf": refs,
    }
    (HERE / "event.schema.json").write_text(json.dumps(env, indent=2) + "\n")
    print(f"wrote {len(EVENTS)} event schemas + envelope")


if __name__ == "__main__":
    main()
