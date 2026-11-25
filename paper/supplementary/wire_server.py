"""A wire front-end for the Python reference bridge.

``WireServer.handle`` takes the bytes of one client request (Appendix B),
decodes them, dispatches the op to a ``Bridge`` and returns the bytes of the
response.  Signed ops are verified by the bridge itself, from the fields of
the message and the registry of client keys, so a request is accepted or
refused as the envelope states it, not as a harness constructs it.

Ops handled: ``attach``, ``challenge``, ``add_client``, ``reattach``,
``join``, ``disconnect``, ``escalate``, ``resolve``, ``submit_tool_call``,
``answer_tool_call``, ``delivered``, ``completed``, ``narrow``, ``extend``
and ``terminate``, and the operator events ``revoke``, ``add_key`` and
``operator_terminate``, which carry the operator's signature.  ``attach``
carries the scope grant and the client's proof of possession, so it needs no
transport check; the operator events are verified by the bridge against the
operator key.  A ``revoke`` that carries no signature is a client's request
for a revocation and is treated as an unsigned op.  Any other op is refused
as ``unsupported_op``.  A request that is not canonical JSON, that is nested
deeper than ``MAX_DEPTH`` or whose fields are missing or of the wrong type
is refused as ``bad_canonical``.
"""
from __future__ import annotations

from typing import Any

import conformance_suite as cs
import wire


class WireRejected(cs.BridgeError):
    """A response with ``status: "rejected"``; ``reason`` is its reason."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"wire rejected: {reason}")
        self.reason = reason


def _reason(exc: cs.BridgeError) -> str:
    """The reason name of a refusal: the typed ``reason`` the raise site
    set (``refused`` when it names nothing).  The message text is never
    read."""
    return exc.reason


# Ops that carry no signature of their own (Appendix B, "Authentication of
# unsigned ops"): the transport binding authenticates their caller.
UNSIGNED_OPS = frozenset({
    "disconnect", "escalate", "submit_tool_call", "answer_tool_call",
    "resolve", "delivered", "completed", "narrow", "extend", "terminate"})

# No message of Appendix B nests deeper than a tool call's content inside the
# envelope; a request nested deeper than this is refused before it is parsed,
# so a deeply nested body cannot exhaust the parser's stack.
MAX_DEPTH = 32


def nesting_depth(data: bytes) -> int:
    """The deepest nesting of arrays and objects in a JSON text, counted on
    the bytes (brackets inside strings do not count)."""
    depth = deepest = 0
    in_string = escaped = False
    for byte in data:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:            # backslash
                escaped = True
            elif byte == 0x22:            # closing quote
                in_string = False
        elif byte == 0x22:
            in_string = True
        elif byte in (0x5B, 0x7B):        # [ {
            depth += 1
            deepest = max(deepest, depth)
        elif byte in (0x5D, 0x7D):        # ] }
            depth -= 1
    return deepest


def is_unsigned(msg: dict) -> bool:
    """Whether the transport binding must authenticate the caller: the ops
    of ``UNSIGNED_OPS``, and a ``revoke`` without an operator signature (a
    client's request for a revocation, which appends an event on the
    caller's word alone)."""
    if msg["op"] in UNSIGNED_OPS:
        return True
    return (msg["op"] == "revoke" and not msg.get("signature")
            and "requested_by" in msg)


def event_object(ev: cs.Event) -> dict[str, Any]:
    """An event as a wire object (the envelope of ``event.schema.json``)."""
    return {"kind": ev.kind.value, "session_id": ev.session_id,
            "sequence": ev.sequence, "prev_hash": ev.prev_hash,
            "payload": ev.payload, "timestamp": ev.timestamp}


class WireServer:
    """``authenticate(op, message) -> bool`` is the hook where a deployment
    puts its transport-level caller check (a client certificate, a session
    token).  It is called for every unsigned op (``is_unsigned``) before the
    bridge sees it; a false answer refuses the op as ``unauthenticated`` and
    nothing is committed.  With no hook every caller is accepted, which is
    only acceptable for the reference harness."""

    def __init__(self, bridge: cs.Bridge, authenticate=None) -> None:
        self.bridge = bridge
        self.authenticate = authenticate

    def handle(self, data: bytes) -> bytes:
        try:
            if nesting_depth(data) > MAX_DEPTH:
                raise ValueError("nested too deeply")
            msg = wire.decode_message(data)
            if wire.canonical_bytes(msg) != data:
                raise ValueError("not canonical")
            sid = msg.get("session_id", "")
            if not isinstance(sid, str) or not isinstance(msg["op"], str):
                raise ValueError("session_id and op are strings")
        except (ValueError, UnicodeDecodeError, RecursionError):
            return wire.encode_error("", "bad_canonical")
        handler = getattr(self, "_op_" + msg["op"], None)
        if handler is None:
            return wire.encode_error(sid, "unsupported_op")
        if (self.authenticate is not None and is_unsigned(msg)
                and not self.authenticate(msg["op"], msg)):
            return wire.encode_error(sid, "unauthenticated")
        try:
            return handler(sid, msg)
        except cs.BridgeError as exc:
            return wire.encode_error(sid, _reason(exc))
        except (KeyError, TypeError, ValueError):
            return wire.encode_error(sid, "bad_canonical")

    # -- ops ---------------------------------------------------------------

    def _op_attach(self, sid: str, m: dict) -> bytes:
        ident = cs.SessionIdentity(sid, m["principal"], tuple(m["scope"]),
                                   tuple(m["lineage"]))
        key = cs.ClientPublicKey(m["key_id"], m["scheme"],
                                 bytes.fromhex(m["public_key"]))
        self.bridge.attach(ident, key, m.get("grant"), m.get("signature"))
        return wire.encode_response(
            "attached", session_id=sid, seq=0,
            hash=self.bridge.events[sid][0].event_hash())

    def _op_challenge(self, sid: str, m: dict) -> bytes:
        """The nonce is issued for the key id the message names; the answer
        has the same form whatever that key id is."""
        ch = self.bridge.challenge(sid, m["key_id"])
        return wire.encode_response("nonce", session_id=sid,
                                    nonce=ch.nonce, ttl_seconds=ch.ttl_seconds)

    def _op_add_client(self, sid: str, m: dict) -> bytes:
        new = cs.ClientPublicKey(m["new_key_id"], m["scheme"],
                                 bytes.fromhex(m["new_public_key"]))
        self.bridge.add_client_key(sid, m["via_key_id"], new, m["nonce"],
                                   m["signature"])
        return wire.encode_response("added", session_id=sid)

    @staticmethod
    def _request(m: dict) -> cs.ResumeRequest:
        return cs.ResumeRequest(m["key_id"], m["nonce"], m["seq"], m["hash"],
                                m["signature"])

    def _op_reattach(self, sid: str, m: dict) -> bytes:
        """The response carries the events after the acknowledged prefix, as
        event objects."""
        events = self.bridge.client_reattach(sid, self._request(m))
        return wire.encode_response(
            "verified", session_id=sid,
            events=[event_object(e) for e in events or []])

    def _op_join(self, sid: str, m: dict) -> bytes:
        events = self.bridge.join(sid, self._request(m))
        return wire.encode_response(
            "joined", session_id=sid,
            events=[event_object(e) for e in events or []])

    def _op_disconnect(self, sid: str, m: dict) -> bytes:
        self.bridge.client_disconnect(sid, m.get("key_id"), m["reason"])
        return wire.encode_response("disconnected", session_id=sid)

    def _op_escalate(self, sid: str, m: dict) -> bytes:
        self.bridge.escalate_to_human(sid)
        return wire.encode_response("escalated", session_id=sid)

    def _op_resolve(self, sid: str, m: dict) -> bytes:
        self.bridge.human_resolve(sid)
        return wire.encode_response("resolved", session_id=sid)

    def _op_extend(self, sid: str, m: dict) -> bytes:
        """A widening asked for through the bridge is rejected (I3) and the
        response carries the scope in force; one the runtime announced is
        recorded and the revert is requested; a subset is no extension."""
        try:
            out = self.bridge.attempt_authority_extension(
                sid, tuple(m["new_scope"]), source=m["source"])
        except cs.BridgeError as exc:
            if exc.reason != "extension_rejected":
                raise
            return wire.encode_response(
                "rejected", session_id=sid, reason="extension_rejected",
                current_scope=list(self.bridge.scope_of(sid)))
        status = "revert_requested" if out == "REVERT" else "unchanged"
        return wire.encode_response(
            status, session_id=sid,
            current_scope=list(self.bridge.scope_of(sid)))

    def _op_revoke(self, sid: str, m: dict) -> bytes:
        out = self.bridge.revoke_key(
            sid, m["key_id"], m["reason"], signature=m.get("signature"),
            requested_by=m.get("requested_by"))
        return wire.encode_response(out, session_id=sid)

    def _op_add_key(self, sid: str, m: dict) -> bytes:
        self.bridge.operator_add_key(
            sid, m["key_id"], m["public_key"], signature=m.get("signature"),
            scheme=m["scheme"])
        return wire.encode_response("key_added", session_id=sid)

    def _op_operator_terminate(self, sid: str, m: dict) -> bytes:
        self.bridge.operator_terminate(
            sid, m["reason"], signature=m.get("signature"))
        return wire.encode_response("terminated", session_id=sid)

    def _op_submit_tool_call(self, sid: str, m: dict) -> bytes:
        """The response carries the idempotency key of the call: the
        caller's, or the one the bridge generated."""
        out, key = self.bridge.submit_tool_call_keyed(
            sid, m["tool"], key=m.get("key"), permission=m.get("permission"),
            content=m["content"])
        if out == "DUPLICATE":
            return wire.encode_error(sid, "duplicate_key")
        if out == "REJECTED":
            return wire.encode_error(sid, "queue_full")
        return wire.encode_response(out.lower(), session_id=sid, key=key)

    def _op_answer_tool_call(self, sid: str, m: dict) -> bytes:
        self.bridge.answer_tool_call(sid, m["key"], m["shown_hash"],
                                     m["decision"] == "approve")
        return wire.encode_response("answered", session_id=sid)

    def _op_delivered(self, sid: str, m: dict) -> bytes:
        self.bridge.delivered(sid, m["key"])
        return wire.encode_response("delivered", session_id=sid)

    def _op_completed(self, sid: str, m: dict) -> bytes:
        self.bridge.completed(sid, m["key"], m.get("result_hash", ""))
        return wire.encode_response("completed", session_id=sid)

    def _op_narrow(self, sid: str, m: dict) -> bytes:
        version = self.bridge.narrow_authority_scope(sid, tuple(m["new_scope"]))
        return wire.encode_response("narrowed", session_id=sid,
                                    new_version=version)

    def _op_terminate(self, sid: str, m: dict) -> bytes:
        self.bridge.terminate(sid, m["reason"])
        return wire.encode_response("terminated", session_id=sid)


def send(server: WireServer, data: bytes) -> dict[str, Any]:
    """Send a request; return the decoded response, or raise
    ``WireRejected`` for ``status: "rejected"``."""
    resp = wire.decode_response(server.handle(data))
    if resp["status"] == "rejected":
        raise WireRejected(resp["reason"])
    return resp
