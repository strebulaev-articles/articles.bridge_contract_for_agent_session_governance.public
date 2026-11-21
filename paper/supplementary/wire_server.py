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
operator key.  Any other op is refused as ``unsupported_op``.  A request
that is not canonical JSON is refused as ``bad_canonical``.
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


class WireServer:
    """``authenticate(op, message) -> bool`` is the hook where a deployment
    puts its transport-level caller check (a client certificate, a session
    token).  It is called for every op in ``UNSIGNED_OPS`` before the bridge
    sees it; a false answer refuses the op as ``unauthenticated`` and nothing
    is committed.  With no hook every caller is accepted, which is only
    acceptable for the reference harness."""

    def __init__(self, bridge: cs.Bridge, authenticate=None) -> None:
        self.bridge = bridge
        self.authenticate = authenticate

    def handle(self, data: bytes) -> bytes:
        try:
            msg = wire.decode_message(data)
            if wire.canonical_bytes(msg) != data:
                raise ValueError("not canonical")
        except (ValueError, UnicodeDecodeError):
            return wire.encode_error("", "bad_canonical")
        sid = msg.get("session_id", "")
        handler = getattr(self, "_op_" + str(msg["op"]), None)
        if handler is None:
            return wire.encode_error(sid, "unsupported_op")
        if (self.authenticate is not None and msg["op"] in UNSIGNED_OPS
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
        ch = self.bridge.challenge(sid)
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
        events = self.bridge.client_reattach(sid, self._request(m))
        return wire.encode_response(
            "verified", session_id=sid,
            events=[e.kind.value for e in events or []])

    def _op_join(self, sid: str, m: dict) -> bytes:
        events = self.bridge.join(sid, self._request(m))
        return wire.encode_response(
            "joined", session_id=sid,
            events=[e.kind.value for e in events or []])

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
        out = self.bridge.submit_tool_call(
            sid, m["tool"], key=m.get("key"), permission=m.get("permission"),
            content=m["content"])
        if out == "DUPLICATE":
            return wire.encode_error(sid, "duplicate_key")
        if out == "REJECTED":
            return wire.encode_error(sid, "queue_full")
        return wire.encode_response(out.lower(), session_id=sid)

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
        self.bridge.narrow_authority_scope(sid, tuple(m["new_scope"]))
        return wire.encode_response("narrowed", session_id=sid)

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
