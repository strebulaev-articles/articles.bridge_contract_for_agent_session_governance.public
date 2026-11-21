#!/usr/bin/env python3
"""
Run the language-neutral vectors in ``vectors/*.json`` against the Python
reference bridge, and (with ``--check-paper FILE``) check that the vector
table in the paper lists exactly the files that exist.

    python3 -I run_vectors.py
    python3 -I run_vectors.py --check-paper ../sections/generated_vectors.tex
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))      # python -I does not add the script directory

import conformance_suite as cs  # noqa: E402
import wire  # noqa: E402
import wire_server  # noqa: E402

VECTORS = sorted((HERE / "vectors").glob("V*.json"))


def cell_name(cell: cs.Cell) -> list[str]:
    if cell.life == cs.Lifecycle.TERMINATED:
        return ["Terminated"]
    return [cell.att.value, cell.human.value]


class Runner:
    def __init__(self, vec: dict) -> None:
        self.vec = vec
        # Checkpoints are off unless the vector says it ``requires``
        # them: the Rust crate does not implement I-CHECKPOINT, so every
        # other vector must hold without CHECKPOINT events, and a vector
        # that requires them is Python-only (the Rust runner skips it).
        defaults = {"n_checkpoint": 10**9, "t_checkpoint": float("inf")}
        if "checkpoint" in vec.get("requires", []):
            defaults.update(vec.get("config", {}))
        else:
            vec_cfg = dict(vec.get("config", {}))
            vec_cfg.pop("n_checkpoint", None)
            vec_cfg.pop("t_checkpoint", None)
            defaults.update(vec_cfg)
        cfg = cs.Config(**defaults)
        self.cfg = cfg
        self.clock = cs.FakeClock(1000.0)
        self.storage = cs.Storage()
        s = vec["session"]
        self.sid = s["session_id"]
        self.scheme = s.get("scheme", cs.SCHEME_ED25519)
        self.keys = {s["client_key_id"]: cs.ClientKey(
            s["client_key_id"], scheme=self.scheme)}
        self.first = s["client_key_id"]
        self.bridge = cs.Bridge(
            self.storage, self.clock, cfg,
            cs.OperatorGrantVerifier(cs.TEST_OPERATOR.public_key))
        identity = cs.SessionIdentity(
            self.sid, s["principal_id"], tuple(s["authority_scope"]), ())
        self.attach_refused = False
        self.attach_reason: str | None = None
        self.others: dict[tuple[str, str], cs.ClientKey] = {}
        try:
            self._attach(identity, self.keys[self.first].public(),
                         self.grant(s.get("grant", "ok"), identity),
                         self.possession(s.get("possession", "ok"), identity))
        except (cs.GrantInvalid, cs.PossessionInvalid,
                wire_server.WireRejected) as exc:
            if exc.reason not in ("grant_invalid", "possession_invalid"):
                raise
            self.attach_refused = True
            self.attach_reason = exc.reason
        self.seen: dict[str, tuple[int, str]] = {}
        self.nonces: dict[str, str] = {}
        self.last_add: tuple[str, str, str] = ("", "", "")
        if not self.attach_refused:
            self.sync(self.first)

    def _attach(self, identity: cs.SessionIdentity, key: cs.ClientPublicKey,
                grant: str | None, proof: str | None) -> None:
        self.bridge.attach(identity, key, grant, proof)

    def grant(self, kind: str, identity: cs.SessionIdentity) -> str | None:
        """The grant a vector's session presents: ``ok``, ``none``,
        ``forged`` (another authority), ``other-session`` or
        ``wider-scope`` (a grant for a different identity), ``other-key``
        (a grant for another public key under the same key id) or
        ``other-bridge`` (a grant made for a different bridge)."""
        key = self.keys[self.first].public()
        operator = cs.TEST_OPERATOR
        if kind == "ok":
            return operator.grant(identity, key)
        if kind == "none":
            return None
        if kind == "forged":
            return cs.OperatorKey(b"\x09" * 32).grant(identity, key)
        if kind == "other-session":
            return operator.grant(cs.SessionIdentity(
                identity.session_id + "-x", identity.principal_id,
                identity.authority_scope, identity.task_lineage), key)
        if kind == "wider-scope":
            return operator.grant(cs.SessionIdentity(
                identity.session_id, identity.principal_id,
                identity.authority_scope[:1], identity.task_lineage), key)
        if kind == "other-key":
            return operator.grant(identity, cs.ClientKey(
                self.first, scheme=self.scheme).public())
        if kind == "other-bridge":
            return operator.grant(identity, key, "bridge-elsewhere")
        raise ValueError(f"unknown grant kind {kind!r}")

    def possession(self, kind: str, identity: cs.SessionIdentity) -> str | None:
        """The proof of possession a vector's session presents: ``ok``,
        ``none``, ``wrong-key`` (a signature by another key of the same
        scheme) or ``other-bridge`` (a proof made for a different bridge)."""
        key = self.keys[self.first]
        if kind == "ok":
            return key.prove_attach(identity)
        if kind == "none":
            return None
        if kind == "wrong-key":
            return cs.ClientKey(self.first, scheme=self.scheme).prove_attach(
                identity)
        if kind == "other-bridge":
            return key.prove_attach(identity, "bridge-elsewhere")
        raise ValueError(f"unknown possession kind {kind!r}")

    def cell(self) -> list[str]:
        return cell_name(self.bridge.cell_of(self.sid))

    def tip(self) -> tuple[int, str]:
        ev = self.storage.logs[self.sid][-1]
        return ev.sequence, ev.event_hash()

    def sync(self, client: str) -> None:
        self.seen[client] = self.tip()

    def _key(self, client: str) -> cs.ClientKey:
        if client not in self.keys:              # a key nobody registered
            self.keys[client] = cs.ClientKey(client, scheme=self.scheme)
        return self.keys[client]

    def fresh_nonce(self) -> str:
        return self.bridge.challenge(self.sid).nonce

    def _request(self, act: dict, op: str = "reattach") -> cs.ResumeRequest:
        client = act.get("client", self.first)
        key = self._key(client)
        which = act.get("nonce", "fresh")
        if which == "fresh":
            nonce = self.fresh_nonce()
        elif which == "unknown":
            nonce = "ab" * 16
        elif which == "other-session":  # issued for a second session
            nonce = self.bridge.challenge(act["from_session"]).nonce
        else:
            nonce = self.nonces[which]
        if "as" in act:
            self.nonces[act["as"]] = nonce
        tip_seq, tip_hash = self.tip()
        seq, h = self.seen.get(client, (0, self.storage.logs[self.sid][0].event_hash()))
        prefix = act.get("prefix", "seen")
        if prefix == "tip":
            seq, h = tip_seq, tip_hash
        elif prefix == "hash-mismatch":
            h = "00" * 32
        elif prefix == "beyond":
            seq = tip_seq + 5
        req = key.request(self.sid, nonce, seq, h, op)
        proof = act.get("proof", "valid")
        if proof == "invalid":
            req.signature = "invalid"
        elif proof == "wrong-key":      # a real signature by another key
            req.signature = cs.ClientKey(
                client, scheme=self.scheme).sign(self.sid, nonce, seq, h, op)
        elif proof == "other-message":  # the right key, a different message
            req.signature = key.sign(self.sid, nonce, seq + 1, h, op)
        elif proof == "other-operation":  # the other operation's signature
            req.signature = key.sign(self.sid, nonce, seq, h,
                                     "join" if op == "reattach" else "reattach")
        elif proof == "other-session-key":  # her key, registered in her own
            # session under the same key id
            req.signature = self.others[(act["from_session"], client)].sign(
                self.sid, nonce, seq, h, op)
        elif proof == "no-key-id":      # the tagged tuple without the key id
            req.signature = key.sign_bytes(cs._canon(
                [cs.RESUME_DOMAINS[op], self.sid, nonce, seq, h]))
        elif proof == "untagged":       # the tuple without the domain tag
            req.signature = key.sign_bytes(cs._canon(
                [self.sid, nonce, seq, h]))
        elif proof != "valid":
            raise ValueError(f"unknown proof {proof!r}")
        return req

    def add_client_request(self, act: dict, key: cs.ClientKey):
        """(via key id, nonce, signature) an ``add_client`` action
        presents: the connected client's signature over the tagged tuple
        with a fresh nonce (``proof`` valid), absent (``none``), made by
        another holder of the key id (``forged``), made for a join
        (``other-operation``), or the previous request presented again
        (``replay``)."""
        b = self.bridge
        conn = sorted(b.client_set(self.sid))
        via = act.get("via") or (conn[0] if conn else self.first)
        if act.get("proof") == "replay":
            return self.last_add
        signer = self._key(via)
        if act.get("nonce") == "other-session":   # issued for a second session
            nonce = self.bridge.challenge(act["from_session"]).nonce
        else:
            nonce = self.fresh_nonce()
        proof = act.get("proof", "valid")
        pub = key.public()
        if proof == "valid":
            sig = signer.sign_add_client(self.sid, pub, nonce)
        elif proof == "none":
            sig = ""
        elif proof == "forged":
            sig = cs.ClientKey(via, scheme=self.scheme).sign_add_client(
                self.sid, pub, nonce)
        elif proof == "other-operation":
            seq, h = self.seen.get(
                via, (0, self.storage.logs[self.sid][0].event_hash()))
            sig = signer.sign(self.sid, nonce, seq, h, "join")
        else:
            raise ValueError(f"unknown proof {proof!r}")
        self.last_add = (via, nonce, sig)
        return self.last_add

    def operator_sig(self, act: dict, op: str, *args) -> str | None:
        """The operator signature an action presents: ``ok`` (the operator's
        over this operation at the bridge's current log position, under its
        id), ``none`` (absent), ``forged`` (another key's over this
        operation), ``other-operation`` (the operator's, over a different
        operation of the same session), ``other-bridge`` (the operator's,
        bound to another bridge id) or ``stale`` (the operator's, bound to
        the position of the first event instead of the head)."""
        kind = act.get("sig", "ok")
        operator = cs.TEST_OPERATOR
        bridge = self.bridge
        bridge_id = bridge.bridge_id
        at = bridge.head_of(self.sid)
        if kind == "none":
            return None
        if kind == "forged":
            operator = cs.OperatorKey(b"\x09" * 32)
        elif kind == "other-bridge":
            bridge_id = "bridge-elsewhere"
        elif kind == "stale":
            at = (0, self.storage.logs[self.sid][0].event_hash())
        elif kind == "other-operation":
            others = {"revoke": ("terminate", ("other",)),
                      "add_key": ("revoke", (args[0] if args else "", "compromise")),
                      "terminate": ("revoke", (self.first, "compromise"))}
            other, oargs = others[op]
            return getattr(operator, other)(bridge_id, self.sid, *oargs, *at)
        elif kind != "ok":
            raise ValueError(f"unknown signature kind {kind!r}")
        if op == "add_key":
            return operator.add_key(bridge_id, self.sid, args[0], args[1],
                                    *at, args[2])
        return getattr(operator, op)(bridge_id, self.sid, *args, *at)

    def answer_hash(self, act: dict) -> str:
        """The hash an answer reports: ``shown`` (the call as the bridge
        hashed it), ``content-only`` (the hash of the content alone, what a
        client that approved only the arguments would send) or any other
        value (a hash of something else)."""
        how = act.get("hash", "shown")
        if how == "shown":
            return self.bridge.shown_hash_of(self.sid, act["key"])
        if how == "content-only":
            return cs.content_hash(act["content"])
        return cs.content_hash({"other": True})

    def do(self, act: dict) -> None:
        b, sid, kind = self.bridge, self.sid, act["do"]
        if kind == "disconnect":
            gone = ([act["client"]] if "client" in act
                    else sorted(b.client_set(sid)))
            for c in gone:
                self.sync(c)
            b.client_disconnect(sid, act.get("client"))
        elif kind == "sync":
            self.sync(act["client"])
        elif kind == "escalate":
            b.escalate_to_human(sid)
        elif kind == "resolve":
            if act.get("answer", "all") == "all":
                for c in list(b._sess[sid].queue):
                    if c["answer"] is None:
                        b.answer_tool_call(sid, c["key"], c["shown_hash"], True)
            b.human_resolve(sid)
        elif kind == "answer":
            h = self.answer_hash(act)
            b.answer_tool_call(sid, act["key"], h, act.get("approve", True))
        elif kind == "tool_call":
            b.submit_tool_call(sid, act["tool"], key=act.get("key"),
                               permission=act.get("permission"),
                               content=act.get("content"))
        elif kind == "delivered":
            b.delivered(sid, act["key"])
        elif kind == "completed":
            b.completed(sid, act["key"], act.get("result_hash", ""))
        elif kind == "narrow":
            b.narrow_authority_scope(sid, tuple(act["scope"]))
        elif kind == "extend":
            b.attempt_authority_extension(sid, tuple(act["scope"]),
                                          source=act.get("source", "requested"))
        elif kind == "add_client":
            key = (self.keys[act["client"]] if act.get("proof") == "replay"
                   else cs.ClientKey(act["client"], scheme=self.scheme))
            via, nonce, sig = self.add_client_request(act, key)
            b.add_client_key(sid, via, key.public(), nonce, sig)
            self.keys[act["client"]] = key
            self.sync(act["client"])
        elif kind == "attach_other":
            # a second, validly granted session on the same bridge whose
            # client key carries the given key id
            key = cs.ClientKey(act["client"], scheme=self.scheme)
            ident = cs.SessionIdentity(
                act["session_id"], act.get("principal_id", "user-mallory"),
                tuple(self.vec["session"]["authority_scope"]), ())
            cs.attach_as(b, ident, key)
            self.others[(act["session_id"], act["client"])] = key
        elif kind == "tamper_registry":
            slot = (sid, act["client"])
            how = act["how"]
            if how == "other-key":        # a different public key
                self.storage.client_keys[slot] = cs.ClientKey(
                    act["client"], scheme=self.scheme).public_key
            elif how == "extra":          # a key the log does not record
                stray = cs.ClientKey(act["client"], scheme=self.scheme)
                self.storage.register_key(sid, act["client"], stray.scheme,
                                          stray.public_key)
            elif how == "missing":        # an entry lost from the registry
                self.storage.unregister_key(sid, act["client"])
            else:
                raise ValueError(f"unknown registry tampering {how!r}")
        elif kind == "revoke":
            reason = act.get("reason", "rotation")
            sig = ("" if not act.get("signed", True)
                   else self.operator_sig(act, "revoke", act["client"], reason))
            b.revoke_key(sid, act["client"], reason, signature=sig,
                         requested_by=act.get("requested_by"))
        elif kind == "operator_add_key":
            key = cs.ClientKey(act["client"], scheme=self.scheme)
            pub = key.public_key.hex()
            b.operator_add_key(
                sid, act["client"], pub, scheme=key.scheme,
                signature=self.operator_sig(act, "add_key", act["client"],
                                            pub, key.scheme))
            self.keys[act["client"]] = key
            self.sync(act["client"])
        elif kind == "operator_terminate":
            b.operator_terminate(
                sid, "all_keys_revoked",
                signature=self.operator_sig(act, "terminate",
                                            "all_keys_revoked"))
        elif kind == "challenge":
            nonce = b.challenge(sid).nonce
            if "as" in act:
                self.nonces[act["as"]] = nonce
        elif kind == "challenge_uniform":
            # I11a: the session and a session the bridge never saw are
            # refused with the same text
            texts = []
            for target in (sid, "no-such-session"):
                try:
                    b.challenge(target)
                except cs.BridgeError as exc:
                    texts.append(str(exc))
            assert len(texts) == 2 and texts[0] == texts[1], texts
        elif kind == "reattach_uniform":
            # I11a: a re-attach request for the session and for a session
            # the bridge never saw are refused with the same text
            req = self._request(act, "reattach")
            texts = []
            for target in (sid, "no-such-session"):
                try:
                    b.client_reattach(target, req)
                except cs.BridgeError as exc:
                    texts.append(str(exc))
            assert len(texts) == 2 and texts[0] == texts[1], texts
        elif kind == "reattach_key_uniform":
            # F-8a: a request that names an unregistered key and one whose
            # signature does not verify are refused with the same text
            texts = []
            for variant in ({"client": self.first, "proof": "invalid"},
                            {"client": act["client"]}):
                try:
                    b.begin_resume(sid, self._request(variant, "reattach"))
                except cs.BridgeError as exc:
                    texts.append(str(exc))
            assert len(texts) == 2 and texts[0] == texts[1], texts
        elif kind in ("reattach", "join"):
            req = self._request(act, kind)
            replay = act.get("transport_replay", False)
            if kind == "join":
                b.join(sid, req, transport_replay=replay)
            else:
                b.begin_resume(sid, req, transport_replay=replay)
                if (act.get("complete", True)
                        and b.cell_of(sid).att == cs.Attachment.RESUMING):
                    b.complete_resume(sid)
        elif kind == "complete_resume":
            b.complete_resume(sid)
        elif kind == "advance":
            self.clock.advance(act["seconds"])
            b.tick()
        elif kind == "tick":
            b.tick()
        elif kind == "restart":
            self.clock.advance(act.get("downtime", 0))   # no timers run while down
            self.bridge = cs.Bridge.recover(
                self.storage, self.clock, self.cfg,
                cs.OperatorGrantVerifier(cs.TEST_OPERATOR.public_key))
        elif kind == "plant_malformed_log":
            # a second session whose durable log cannot be replayed
            other = act["session_id"]
            how = act["how"]
            if how == "no-genesis":       # first event is not ATTACHED
                evs = [cs.Event(cs.GE.DETACHMENT, other, 0, "", {}, 1.0)]
            elif how == "missing-field":  # ATTACHED lacks principal_id
                evs = [cs.Event(cs.GE.ATTACHED, other, 0, "",
                                {"client_key_id": "ck-x"}, 1.0)]
            else:
                raise ValueError(f"unknown malformed log {how!r}")
            self.storage.logs[other] = evs
        elif kind == "other_quarantined":
            assert b.is_quarantined(act["session_id"])
        elif kind == "tamper_log":
            ev = self.storage.logs[sid][act["index"]]
            assert act["field"] == "prev_hash"
            ev.prev_hash = "00" * 32
        elif kind == "terminate":
            b.terminate(sid)
        else:
            raise ValueError(f"unknown action {kind!r}")


class WireRunner(Runner):
    """A runner that sends the actions of ``WIRE_ROUTED`` as wire messages
    (Appendix B) to a ``WireServer`` over the same bridge, with the real
    signatures the harness computes, so the bridge verifies them from the
    envelope.  Other actions (session creation, ``resolve``, ``extend``,
    clock and restart hooks, a re-attach left incomplete or flagged as a
    transport replay) are applied to the bridge directly."""

    WIRE_ROUTED = ("challenge", "add_client", "reattach", "join",
                   "disconnect", "escalate", "resolve", "tool_call", "answer",
                   "narrow", "extend", "terminate", "delivered", "completed",
                   "revoke", "operator_add_key", "operator_terminate")

    def __init__(self, vec: dict) -> None:
        self.routed = 0
        super().__init__(vec)

    def _attach(self, identity, key, grant, proof) -> None:
        """Session creation is an ``attach`` message."""
        self.server = wire_server.WireServer(self.bridge)
        self._send(wire.op_attach(
            session_id=identity.session_id, principal=identity.principal_id,
            scope=list(identity.authority_scope),
            lineage=list(identity.task_lineage), key_id=key.key_id,
            scheme=key.scheme, public_key=key.public_key.hex(),
            grant=grant, signature=proof))

    def _send(self, data: bytes) -> dict:
        self.routed += 1
        self.server.bridge = self.bridge          # follows a restart
        return wire_server.send(self.server, data)

    def fresh_nonce(self) -> str:
        return self._send(wire.op_challenge(session_id=self.sid))["nonce"]

    def do(self, act: dict) -> None:
        kind, sid, b = act["do"], self.sid, self.bridge
        if kind == "challenge":
            nonce = self.fresh_nonce()
            if "as" in act:
                self.nonces[act["as"]] = nonce
        elif kind == "add_client":
            key = (self.keys[act["client"]] if act.get("proof") == "replay"
                   else cs.ClientKey(act["client"], scheme=self.scheme))
            via, nonce, sig = self.add_client_request(act, key)
            self._send(wire.op_add_client(
                session_id=sid, via_key_id=via, new_key_id=key.key_id,
                scheme=key.scheme, new_public_key=key.public_key.hex(),
                nonce=nonce, signature=sig))
            self.keys[act["client"]] = key
            self.sync(act["client"])
        elif kind in ("reattach", "join"):
            if (kind == "reattach" and (act.get("transport_replay")
                                        or act.get("complete", True) is False)):
                return super().do(act)
            req = self._request(act, kind)
            send = wire.op_join if kind == "join" else wire.op_reattach
            self._send(send(session_id=sid, key_id=req.key_id,
                            nonce=req.nonce, seq=req.seq, hash=req.hash,
                            signature=req.signature))
        elif kind == "disconnect":
            gone = ([act["client"]] if "client" in act
                    else sorted(b.client_set(sid)))
            for c in gone:
                self.sync(c)
            self._send(wire.op_disconnect(
                session_id=sid, reason="client_disconnect",
                key_id=act.get("client")))
        elif kind == "escalate":
            self._send(wire.op_escalate(session_id=sid))
        elif kind == "tool_call":
            try:
                self._send(wire.op_submit_tool_call(
                    session_id=sid, tool=act["tool"], key=act.get("key"),
                    permission=act.get("permission"),
                    content=act.get("content")))
            except wire_server.WireRejected as exc:
                # a duplicate key or a full queue is answered "rejected" on
                # the wire; the bridge returns normally, as in plain mode
                if exc.reason not in ("duplicate_key", "queue_full"):
                    raise
        elif kind == "answer":
            h = self.answer_hash(act)
            self._send(wire.op_answer_tool_call(
                session_id=sid, key=act["key"], shown_hash=h,
                decision="approve" if act.get("approve", True) else "deny"))
        elif kind == "narrow":
            self._send(wire.op_narrow(session_id=sid,
                                      new_scope=list(act["scope"])))
        elif kind == "resolve":
            if act.get("answer", "all") == "all":
                for c in list(b._sess[sid].queue):
                    if c["answer"] is None:
                        self._send(wire.op_answer_tool_call(
                            session_id=sid, key=c["key"],
                            shown_hash=c["shown_hash"], decision="approve"))
            self._send(wire.op_resolve(session_id=sid))
        elif kind == "extend":
            resp = self._send(wire.op_extend(
                session_id=sid, new_scope=list(act["scope"]),
                source=act.get("source", "requested")))
            assert resp["current_scope"] == list(b.scope_of(sid))
        elif kind == "revoke":
            reason = act.get("reason", "rotation")
            sig = ("" if not act.get("signed", True)
                   else self.operator_sig(act, "revoke", act["client"], reason))
            self._send(wire.op_revoke(
                session_id=sid, key_id=act["client"], reason=reason,
                signature=sig, requested_by=act.get("requested_by")))
        elif kind == "operator_add_key":
            key = cs.ClientKey(act["client"], scheme=self.scheme)
            pub = key.public_key.hex()
            self._send(wire.op_add_key(
                session_id=sid, key_id=act["client"], scheme=key.scheme,
                public_key=pub, signature=self.operator_sig(
                    act, "add_key", act["client"], pub, key.scheme)))
            self.keys[act["client"]] = key
            self.sync(act["client"])
        elif kind == "operator_terminate":
            self._send(wire.op_operator_terminate(
                session_id=sid, reason="all_keys_revoked",
                signature=self.operator_sig(act, "terminate",
                                            "all_keys_revoked")))
        elif kind == "terminate":
            self._send(wire.op_terminate(session_id=sid, reason="terminated"))
        elif kind == "delivered":
            self._send(wire.op_delivered(session_id=sid, key=act["key"]))
        elif kind == "completed":
            self._send(wire.op_completed(
                session_id=sid, key=act["key"],
                result_hash=act.get("result_hash", "")))
        else:
            super().do(act)


def run_vector(vec: dict, runner_cls=Runner) -> list[str]:
    """Return a list of failure messages (empty = pass)."""
    expect = vec["expect"]
    if expect.get("config_error"):
        try:
            Runner(vec)
        except ValueError:
            return []
        return ["expected a configuration error"]
    r = runner_cls(vec)
    fails: list[str] = []
    if expect.get("attach_refused") or r.attach_refused:
        want_reason = expect.get("attach_reason", "grant_invalid")
        if (expect.get("attach_refused") and r.attach_refused
                and r.attach_reason != want_reason):
            fails.append(f"attach refused as {r.attach_reason}, "
                         f"expected {want_reason}")
        if r.attach_refused != bool(expect.get("attach_refused")):
            fails.append(f"attach {'refused' if r.attach_refused else 'accepted'}"
                         f", expected "
                         f"{'refusal' if expect.get('attach_refused') else 'success'}")
        if r.storage.logs:
            fails.append("a refused attach committed events")
        return fails
    actions = [a for a in vec["actions"] for _ in range(a.get("times", 1))]
    for i, act in enumerate(actions):
        try:
            r.do(act)
            refused = False
        except cs.BridgeError as exc:
            refused = True
            if ("reason" in act and act["do"] == "add_client"
                    and getattr(exc, "reason", None) != act["reason"]):
                fails.append(f"action {i} add_client: refused as "
                             f"{getattr(exc, 'reason', str(exc))}, expected "
                             f"{act['reason']}")
            if ("wire_reason" in act and isinstance(exc, wire_server.WireRejected)
                    and exc.reason != act["wire_reason"]):
                fails.append(f"action {i} {act['do']}: refused on the wire as "
                             f"{exc.reason}, expected {act['wire_reason']}")
            if (act.get("sig", "ok") != "ok" and
                    getattr(exc, "reason", None) != "operator_signature_invalid"):
                fails.append(f"action {i} {act['do']}: refused as "
                             f"{exc!s}, expected operator_signature_invalid")
        if refused != bool(act.get("error", False)):
            fails.append(f"action {i} {act['do']}: "
                         f"{'refused' if refused else 'accepted'}, expected "
                         f"{'refusal' if act.get('error') else 'success'}")
        if "then_cell" in act and r.cell() != act["then_cell"]:
            fails.append(f"action {i} {act['do']}: cell {r.cell()} != "
                         f"{act['then_cell']}")
    log = r.bridge.events[r.sid]
    got = [e.kind.value for e in log]
    if got != expect["events"]:
        fails.append(f"events\n   got  {got}\n   want {expect['events']}")
    if r.cell() != expect["cell"]:
        fails.append(f"cell {r.cell()} != {expect['cell']}")
    if r.bridge.scope_versions[r.sid] != expect["scope_version"]:
        fails.append("scope_version "
                     f"{r.bridge.scope_versions[r.sid]} != "
                     f"{expect['scope_version']}")
    for other, want in expect.get("other_events", {}).items():
        got_other = [e.kind.value for e in r.storage.logs.get(other, [])]
        if got_other != want:
            fails.append(f"events of {other}\n   got  {got_other}\n   "
                         f"want {want}")
    if "queue" in expect:
        keys = [c["key"] for c in r.bridge._sess[r.sid].queue]
        if keys != expect["queue"]:
            fails.append(f"queue {keys} != {expect['queue']}")
    if "clients" in expect:
        got_clients = sorted(r.bridge.client_set(r.sid))
        if got_clients != expect["clients"]:
            fails.append(f"clients {got_clients} != {expect['clients']}")
    if "key_exhausted" in expect and (
            r.bridge._sess[r.sid].key_exhausted != expect["key_exhausted"]):
        fails.append(f"key_exhausted {r.bridge._sess[r.sid].key_exhausted} != "
                     f"{expect['key_exhausted']}")
    if "revoked" in expect and (
            sorted(r.bridge._sess[r.sid].revoked_keys) != expect["revoked"]):
        fails.append(f"revoked {sorted(r.bridge._sess[r.sid].revoked_keys)} != "
                     f"{expect['revoked']}")
    if "quarantined" in expect and (
            r.bridge.is_quarantined(r.sid) != expect["quarantined"]):
        fails.append(f"quarantined {r.bridge.is_quarantined(r.sid)} != "
                     f"{expect['quarantined']}")
    if "registry" in expect and (
            sorted(r.storage.registered_key_ids(r.sid)) != expect["registry"]):
        fails.append(f"registry {sorted(r.storage.registered_key_ids(r.sid))}"
                     f" != {expect['registry']}")
    if "reverts" in expect and len(r.bridge.revert_requests) != expect["reverts"]:
        fails.append(f"reverts {len(r.bridge.revert_requests)} != "
                     f"{expect['reverts']}")
    if "forwarded_calls" in expect:
        got = {k: v for (s, k), v in r.bridge.forwarded_calls.items()
               if s == r.sid}
        if got != expect["forwarded_calls"]:
            fails.append(f"forwarded calls {got} != {expect['forwarded_calls']}")
    if "forwarded" in expect:
        keys = [k for _, k, _ in r.bridge.forwarded]
        if keys != expect["forwarded"]:
            fails.append(f"forwarded {keys} != {expect['forwarded']}")
    for k, want in expect.get("last_event_payload", {}).items():
        if log[-1].payload.get(k) != want:
            fails.append(f"last event payload[{k!r}] = "
                         f"{log[-1].payload.get(k)!r} != {want!r}")
    return fails


def _tex(s: str) -> str:
    return (s.replace("\\", "\\textbackslash{}").replace("_", "\\_\\allowbreak{}")
             .replace("&", "\\&").replace("#", "\\#").replace("%", "\\%"))


def _act(a: dict) -> str:
    extra = []
    for k in ("client", "session_id", "how", "reason", "nonce", "prefix", "key",
              "seconds", "downtime", "scope", "source", "hash", "times"):
        if k in a:
            extra.append(str(a[k]) if k != "scope" else "[" + ",".join(a[k]) + "]")
    if a.get("complete") is False:
        extra.append("no-complete")
    if a.get("transport_replay"):
        extra.append("replay")
    if a.get("proof") == "invalid":
        extra.append("bad-signature")
    elif a.get("proof") in ("wrong-key", "other-message",
                            "other-session-key", "other-operation",
                            "forged", "none", "replay"):
        extra.append(a["proof"])
    if "requested_by" in a:
        extra.append("requested")
    if a.get("signed") is False:
        extra.append("unsigned")
    if a.get("sig", "ok") != "ok":
        extra.append("sig-" + a["sig"])
    if a.get("answer") == "none":
        extra.append("no-answers")
    name = a["do"] + ("(" + ",".join(extra) + ")" if extra else "")
    return name + ("!" if a.get("error") else "")


def emit_tex() -> str:
    """The paper's vector table, generated from vectors/*.json."""
    rows = []
    for p in sorted(VECTORS, key=lambda q: int(re.sub(r"\D", "", q.stem))):
        v = json.loads(p.read_text())
        e = v["expect"]
        if e.get("config_error"):
            acts, evs, fin = "(construct bridge)", "---", "configuration error"
        elif e.get("attach_refused"):
            how = (f"grant {v['session']['grant']}" if "grant" in v["session"]
                   else f"possession {v['session'].get('possession', 'ok')}")
            acts = f"attach with {how}"
            reason = e.get("attach_reason", "grant_invalid")
            evs, fin = f"(none: attach refused, {reason})", "no session"
        else:
            acts = "; ".join(_act(a) for a in v["actions"]) or "---"
            evs = ", ".join(e["events"])
            fin = "/".join(e["cell"]) + (f", sv={e['scope_version']}"
                                         if e["scope_version"] else "")
        rows.append(f"\\texttt{{{v['id']}}} & {_tex(v['title'])} & "
                    f"\\texttt{{{_tex(acts)}}} & "
                    f"\\texttt{{{_tex(evs)}}} & {fin} \\\\")
    hdr = ("\\toprule\n\\textbf{ID} & \\textbf{Scenario} & "
           "\\textbf{Actions} & \\textbf{Expected event kinds} & "
           "\\textbf{Final cell} \\\\\n\\midrule\n")
    head = ("% GENERATED by supplementary/run_vectors.py --emit-tex; "
            "do not edit.\n"
            "\\begingroup\\scriptsize\\setlength{\\tabcolsep}{3pt}\n"
            "\\begin{longtable}{@{}p{0.05\\columnwidth} "
            ">{\\raggedright\\arraybackslash}p{0.17\\columnwidth} "
            ">{\\raggedright\\arraybackslash}p{0.21\\columnwidth} "
            ">{\\raggedright\\arraybackslash}p{0.38\\columnwidth} "
            ">{\\raggedright\\arraybackslash}p{0.11\\columnwidth}@{}}\n"
            "\\caption{Language-neutral test vectors.}\\label{tab:vectors}\\\\\n"
            + hdr + "\\endfirsthead\n" + hdr + "\\endhead\n")
    foot = "\n\\bottomrule\n\\end{longtable}\n\\endgroup\n"
    return head + "\n".join(rows) + foot


def check_paper(path: Path) -> list[str]:
    """The generated table committed to the paper must match the files."""
    want = emit_tex()
    if not path.exists() or path.read_text() != want:
        return [f"{path} is stale; run run_vectors.py --emit-tex {path}"]
    return []


VECTORS_FIRST_ID = json.loads(VECTORS[0].read_text())["id"]


def wire_probes() -> list[str]:
    """Requests the server must refuse whatever the vectors say: bytes that
    are not canonical JSON, and an op it does not serve."""
    storage = cs.Storage()
    bridge = cs.Bridge(storage, cs.FakeClock(1000.0), cs.Config(),
                       cs.OperatorGrantVerifier(cs.TEST_OPERATOR.public_key))
    server = wire_server.WireServer(bridge)
    fails = []
    for data, reason in (
            (b'{"session_id": "x", "op": "challenge"}', "bad_canonical"),
            (b'{"op":"challenge","session_id":"x"', "bad_canonical"),
            (wire.encode_message("restart"), "unsupported_op"),
            (wire.op_challenge(session_id="unknown"), "refused")):
        got = wire.decode_response(server.handle(data))
        if got.get("status") != "rejected" or got.get("reason") != reason:
            fails.append(f"wire probe {data!r}: {got}, expected {reason}")
    return fails


def run_vector_wire(vec: dict) -> list[str]:
    """Wire mode.  The vector runs through the wire server: actions in
    ``WireRunner.WIRE_ROUTED`` are sent as Appendix B messages with real
    signatures and the bridge verifies them from the envelope, then the
    same expectations are checked as in plain mode.  The remaining actions
    are encoded and decoded (no dummy signature reaches a bridge) so that
    every action has a wire form or is named as having none."""
    import wire
    fails = run_vector(vec, WireRunner)
    if vec["id"] == VECTORS_FIRST_ID:
        fails.extend(wire_probes())
    for a in vec.get("actions", []):
        do = a["do"]
        if do in WireRunner.WIRE_ROUTED:
            continue
        try:
            msg = _encode_action_wire(do, a, vec)
            if msg is None:
                continue  # no wire op-type (e.g. advance, tamper_log)
            if "op" not in wire.decode_message(msg):
                fails.append(f"wire roundtrip {do}: no 'op' field after decode")
        except Exception as e:
            fails.append(f"wire roundtrip {do}: {e}")
    return fails


def _encode_action_wire(do: str, a: dict, vec: dict) -> bytes | None:
    """Encode one vector action as a wire message. Returns None for
    actions that have no wire op-type (clock advances, log tampering,
    bridge restart as a test hook)."""
    import wire
    sid = vec["session"]["session_id"]
    if do == "attach":
        return wire.op_attach(
            session_id=sid, principal=a.get("principal", "p"),
            scope=a.get("scope", []), lineage=a.get("lineage", []),
            key_id=a.get("key", "ck-1"), scheme="ed25519",
            public_key=a.get("public_key", "ab" * 32),
            grant=a.get("grant", "00" * 64),
            signature="00" * 64)
    if do == "add_client":
        return wire.op_add_client(
            session_id=sid, via_key_id=a.get("via", "ck-1"),
            new_key_id=a.get("key", "ck-2"), scheme="ed25519",
            new_public_key="cd" * 32, nonce="n1", signature="00" * 64)
    if do == "challenge":
        return wire.op_challenge(session_id=sid)
    if do == "reattach":
        return wire.op_reattach(
            session_id=sid, key_id=a.get("client", "ck-1"),
            nonce=a.get("nonce", "n1"), seq=a.get("seq", 0),
            hash=a.get("hash", "h"), signature="00" * 64)
    if do == "join":
        return wire.op_join(
            session_id=sid, key_id=a.get("client", "ck-1"),
            nonce=a.get("nonce", "n1"), seq=a.get("seq", 0),
            hash=a.get("hash", "h"), signature="00" * 64)
    if do == "disconnect":
        return wire.op_disconnect(
            session_id=sid, reason=a.get("reason", "client_disconnect"),
            key_id=a.get("client"))
    if do == "escalate":
        return wire.op_escalate(session_id=sid)
    if do == "resolve":
        return wire.op_resolve(session_id=sid)
    if do == "tool_call":
        return wire.op_submit_tool_call(
            session_id=sid, tool=a.get("tool", "t"),
            content=a.get("content", {}), key=a.get("key"),
            permission=a.get("permission"))
    if do == "answer":
        return wire.op_answer_tool_call(
            session_id=sid, key=a.get("key", "k1"),
            shown_hash=a.get("shown_hash", "00" * 32),
            decision="approve" if a.get("answer") != "deny" else "deny")
    if do == "delivered":
        return wire.op_delivered(session_id=sid, key=a.get("key", "k1"))
    if do == "completed":
        return wire.op_completed(session_id=sid, key=a.get("key", "k1"))
    if do == "narrow":
        return wire.op_narrow(
            session_id=sid, new_scope=a.get("scope", []))
    if do == "extend":
        return wire.op_extend(
            session_id=sid, new_scope=a.get("scope", []),
            source=a.get("source", "requested"))
    if do == "terminate":
        return wire.op_terminate(
            session_id=sid, reason=a.get("reason", "terminated"))
    if do == "tick":
        return wire.op_tick(session_id=sid)
    # Actions with no wire op-type: advance, restart (test hook),
    # tamper_log, complete_resume (a reattach sub-step).
    return None


def _flag_path(argv: list[str], flag: str) -> Path:
    i = argv.index(flag) + 1
    if i >= len(argv) or argv[i].startswith("--"):
        sys.exit(f"usage: {flag} requires a file path")
    return Path(argv[i])


def main(argv: list[str]) -> int:
    if "--emit-tex" in argv:
        _flag_path(argv, "--emit-tex").write_text(emit_tex())
        return 0
    wire_mode = "--wire" in argv
    paper = _flag_path(argv, "--check-paper") if "--check-paper" in argv else None
    bad = 0
    for p in VECTORS:
        vec = json.loads(p.read_text())
        try:
            fails = run_vector_wire(vec) if wire_mode else run_vector(vec)
        except Exception as e:  # an unexpected exception is a failed vector, not a crash
            fails = [f"uncaught {type(e).__name__}: {e}"]
        print(f"{'ok  ' if not fails else 'FAIL'} {vec['id']} {vec['title']}")
        for f in fails:
            print("   ", f)
        bad += bool(fails)
    if paper:
        for msg in check_paper(paper):
            print("FAIL", msg)
            bad += 1
    mode = " (wire mode)" if wire_mode else ""
    print(f"\n{len(VECTORS)} vectors{mode}: "
          f"{'all passed' if not bad else str(bad) + ' failure(s)'}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
