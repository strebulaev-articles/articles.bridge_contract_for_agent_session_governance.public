"""Wire-format helpers for the Bridge Contract client--bridge protocol.

This module provides the canonical encoding, message construction,
signature computation, and parsing helpers that the conformance suite
and the wire-level vectors (V44--V51) use. The wire format itself is
specified normatively in Appendix B of the paper.

Canonicalisation is RFC 8785 (JCS), implemented in ``jcs.py`` for the
value types the contract uses (strings, integers up to 2**53, finite
floats, arrays, objects); the Rust crate implements the same rules and the
known-answer vectors in ``vectors/bytes_kat.json`` pin the bytes.
"""
from __future__ import annotations

import json
from typing import Any, Optional

from jcs import canonicalize


def canonical_bytes(obj: Any) -> bytes:
    """RFC 8785 (JCS) compatible canonical JSON encoding of ``obj``.

    Used for: (a) the signature input of ``attach``, ``add_client``,
    ``reattach`` and ``join``; (b) the wire-encoding of any message
    before it is sent. Two implementations that produce the same
    ``canonical_bytes`` for the same logical message are byte-compatible.
    """
    return canonicalize(obj)


def canonical_for_signature(values: list) -> bytes:
    """The signature input: canonical JSON of a JSON array.

    The three signed op-types sign over:
    - ``attach``: ``["bc/v1/attach", bridge_id, session_id, principal,
      scope, lineage, key_id, scheme, public_key]`` (see
      ``attach_signature_input``)
    - ``add_client``: ``["bc/v1/add-client", session_id, via_key_id,
      new_key_id, scheme, new_public_key, nonce]``
    - ``reattach`` / ``join``: ``["bc/v1/reattach" | "bc/v1/join",
      session_id, key_id, nonce, seq, hash]`` (see ``resume_signature_input``)
    """
    return canonical_bytes(values)


def attach_signature_input(bridge_id: str, session_id: str, principal: str,
                           scope: list, lineage: list, key_id: str,
                           scheme: str, public_key: str) -> bytes:
    """The bytes the attaching key signs to prove it holds the private key:
    the attach tag, the bridge, the session, the principal, the granted
    scope and lineage, and the key (id, scheme tag, public key in hex)."""
    return canonical_for_signature(
        ["bc/v1/attach", bridge_id, session_id, principal, list(scope),
         list(lineage), key_id, scheme, public_key])


def add_client_signature_input(session_id: str, via_key_id: str,
                               new_key_id: str, scheme: str,
                               new_public_key: str, nonce: str) -> bytes:
    """The bytes a connected key signs to authorise a further key."""
    return canonical_for_signature(
        ["bc/v1/add-client", session_id, via_key_id, new_key_id, scheme,
         new_public_key, nonce])


def resume_signature_input(op: str, session_id: str, key_id: str,
                           nonce: str, seq: int, hash: str) -> bytes:
    """The bytes a client signs to re-attach or join: the operation tag,
    the session, the signing key id, the nonce and the last event held."""
    tag = {"reattach": "bc/v1/reattach", "join": "bc/v1/join"}[op]
    return canonical_for_signature([tag, session_id, key_id, nonce, seq, hash])


def encode_message(op: str, *, session_id: Optional[str] = None,
                   **fields: Any) -> bytes:
    """Encode a client->bridge request as canonical JSON bytes.

    The envelope is ``{"op": <op>, "session_id": <sid>, ...fields...}``.
    ``session_id`` is omitted when ``None`` (used by ``restart`` and
    by ``tick`` without a session).
    """
    msg: dict[str, Any] = {"op": op}
    if session_id is not None:
        msg["session_id"] = session_id
    msg.update(fields)
    return canonical_bytes(msg)


def decode_message(data: bytes) -> dict[str, Any]:
    """Decode a client->bridge request from bytes.

    Raises ``ValueError`` if the bytes are not valid JSON or if the
    decoded object lacks an ``op`` field.
    """
    obj = json.loads(data.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("wire message must be a JSON object")
    if "op" not in obj:
        raise ValueError("wire message must have an 'op' field")
    return obj


def encode_response(status: str, *, session_id: Optional[str] = None,
                    **fields: Any) -> bytes:
    """Encode a bridge->client response as canonical JSON bytes."""
    msg: dict[str, Any] = {"status": status}
    if session_id is not None:
        msg["session_id"] = session_id
    msg.update(fields)
    return canonical_bytes(msg)


def decode_response(data: bytes) -> dict[str, Any]:
    """Decode a bridge->client response from bytes.

    Raises ``ValueError`` if the bytes are not valid JSON or if the
    decoded object lacks a ``status`` field.
    """
    obj = json.loads(data.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("wire response must be a JSON object")
    if "status" not in obj:
        raise ValueError("wire response must have a 'status' field")
    return obj


def encode_error(session_id: str, reason: str) -> bytes:
    """Encode a bridge->client error response as canonical JSON bytes."""
    return canonical_bytes(
        {"status": "rejected", "session_id": session_id, "reason": reason})


# --- op-type constructors --------------------------------------------------
#
# Each constructor builds the canonical request bytes for one op-type.
# The signature, where required, is computed by the caller and passed
# in; these helpers do not sign.


def op_attach(*, session_id: str, principal: str, scope: list[str],
              lineage: list[str], key_id: str, scheme: str,
              public_key: str, grant: Optional[str],
              signature: Optional[str]) -> bytes:
    """``grant`` or ``signature`` of ``None`` is left out of the message (a
    request that carries none), which the bridge refuses."""
    fields: dict[str, Any] = dict(
        principal=principal, scope=scope, lineage=lineage, key_id=key_id,
        scheme=scheme, public_key=public_key)
    if grant is not None:
        fields["grant"] = grant
    if signature is not None:
        fields["signature"] = signature
    return encode_message("attach", session_id=session_id, **fields)


def op_add_client(*, session_id: str, via_key_id: str, new_key_id: str,
                  scheme: str, new_public_key: str, nonce: str,
                  signature: str) -> bytes:
    return encode_message(
        "add_client", session_id=session_id, via_key_id=via_key_id,
        new_key_id=new_key_id, scheme=scheme, new_public_key=new_public_key,
        nonce=nonce, signature=signature)


def op_challenge(*, session_id: str) -> bytes:
    return encode_message("challenge", session_id=session_id)


def op_reattach(*, session_id: str, key_id: str, nonce: str, seq: int,
                hash: str, signature: str) -> bytes:
    return encode_message(
        "reattach", session_id=session_id, key_id=key_id, nonce=nonce,
        seq=seq, hash=hash, signature=signature)


def op_join(*, session_id: str, key_id: str, nonce: str, seq: int,
            hash: str, signature: str) -> bytes:
    return encode_message(
        "join", session_id=session_id, key_id=key_id, nonce=nonce,
        seq=seq, hash=hash, signature=signature)


def op_disconnect(*, session_id: str, reason: str,
                  key_id: Optional[str] = None) -> bytes:
    fields: dict[str, Any] = {"reason": reason}
    if key_id is not None:
        fields["key_id"] = key_id
    return encode_message("disconnect", session_id=session_id, **fields)


def op_escalate(*, session_id: str, trigger: Optional[str] = None) -> bytes:
    fields: dict[str, Any] = {}
    if trigger is not None:
        fields["trigger"] = trigger
    return encode_message("escalate", session_id=session_id, **fields)


def op_resolve(*, session_id: str) -> bytes:
    return encode_message("resolve", session_id=session_id)


def op_submit_tool_call(*, session_id: str, tool: str, content: dict,
                        key: Optional[str] = None,
                        permission: Optional[str] = None) -> bytes:
    fields: dict[str, Any] = {"tool": tool, "content": content}
    if key is not None:
        fields["key"] = key
    if permission is not None:
        fields["permission"] = permission
    return encode_message(
        "submit_tool_call", session_id=session_id, **fields)


def op_answer_tool_call(*, session_id: str, key: str, shown_hash: str,
                        decision: str) -> bytes:
    return encode_message(
        "answer_tool_call", session_id=session_id, key=key,
        shown_hash=shown_hash, decision=decision)


def op_delivered(*, session_id: str, key: str) -> bytes:
    return encode_message("delivered", session_id=session_id, key=key)


def op_completed(*, session_id: str, key: str,
                 result_hash: Optional[str] = None) -> bytes:
    fields: dict[str, Any] = {"key": key}
    if result_hash is not None:
        fields["result_hash"] = result_hash
    return encode_message(
        "completed", session_id=session_id, **fields)


def op_narrow(*, session_id: str, new_scope: list[str]) -> bytes:
    return encode_message(
        "narrow", session_id=session_id, new_scope=new_scope)


def op_extend(*, session_id: str, new_scope: list[str],
              source: str) -> bytes:
    return encode_message(
        "extend", session_id=session_id, new_scope=new_scope, source=source)


def op_terminate(*, session_id: str, reason: str) -> bytes:
    return encode_message(
        "terminate", session_id=session_id, reason=reason)


def op_revoke(*, session_id: str, key_id: str, reason: str,
              signature: Optional[str] = None,
              requested_by: Optional[str] = None) -> bytes:
    """An operator revocation (``signature``: the operator's, over
    ``["bc/v1/revoke", bridge_id, sid, key_id, reason, seq, head]``); with
    ``requested_by`` and an empty signature it is only a request."""
    fields: dict[str, Any] = {"key_id": key_id, "reason": reason}
    if signature is not None:
        fields["signature"] = signature
    if requested_by is not None:
        fields["requested_by"] = requested_by
    return encode_message("revoke", session_id=session_id, **fields)


def op_add_key(*, session_id: str, key_id: str, scheme: str,
               public_key: str, signature: Optional[str] = None) -> bytes:
    """An operator key addition to a key_exhausted session."""
    fields: dict[str, Any] = {"key_id": key_id, "scheme": scheme,
                              "public_key": public_key}
    if signature is not None:
        fields["signature"] = signature
    return encode_message("add_key", session_id=session_id, **fields)


def op_operator_terminate(*, session_id: str, reason: str,
                          signature: Optional[str] = None) -> bytes:
    """An operator termination of a key_exhausted session."""
    fields: dict[str, Any] = {"reason": reason}
    if signature is not None:
        fields["signature"] = signature
    return encode_message("operator_terminate", session_id=session_id,
                          **fields)


def op_tick(*, session_id: Optional[str] = None) -> bytes:
    return encode_message("tick", session_id=session_id)


def op_restart() -> bytes:
    return encode_message("restart")
