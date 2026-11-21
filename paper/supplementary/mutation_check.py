#!/usr/bin/env python3
"""
Mutation check for the Bridge Contract reference suite.

For each invariant (I1..I15 and the timer bounds) there is at least one mutant: a one-site
textual change to ``conformance_suite.py`` that violates that invariant.
Each mutant is written to a scratch directory and the whole suite is run
against it.  A mutant is *killed* only if pytest exits with code 1 and
reports at least one failed test (an assertion or a raised error in a test);
a collection error, an import error or a syntax error (other exit codes, or
no failed test) is reported as ERROR, never as a kill.  The failing test ids
are recorded, and a kill is *attributed* when a failing test carries the
mutant's invariant tag in its docstring (the traceability tags).  The script
exits non-zero if a patch does not apply exactly once, if an invariant
has no mutant, if a no-change control is not clean, or if any mutant
survives or errors.  Unattributed kills (killed, but by no test tagged with
the mutant's invariant) are listed and make the exit non-zero only with
--strict-attribution.

Run (needs pytest and hypothesis, see requirements.txt):
    python3 -I mutation_check.py [-j N]
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "conformance_suite.py"
# The modules the suite imports (merkle.py is imported inside the checkpoint
# code, so a scratch copy without it fails the checkpoint tests by itself).
SUPPORT = ("conformance_suite.py", "jcs.py", "wire.py", "wire_server.py",
           "merkle.py")

INVARIANTS = ["I1", "I2", "I3", "I4", "I5", "I6", "I7", "I8", "I9", "I10",
              "I11", "I12", "I13", "I14", "I15", "TIMERS"]


FAILED_LINE = re.compile(r"^FAILED \S+?::test_(T\d+[a-z]?)_", re.M)


def classify(proc: subprocess.CompletedProcess) -> tuple[str, list[str]]:
    """Verdict of one pytest run: ("SURVIVED", []), ("killed", failed test ids)
    or ("ERROR (...)", []).  Only exit code 1 with a failed test is a kill."""
    if proc.returncode == 0:
        return "SURVIVED", []
    failed = sorted(set(FAILED_LINE.findall(proc.stdout)))
    if proc.returncode == 1 and failed:
        return "killed", failed
    return (f"ERROR (pytest exit {proc.returncode}, "
            f"{'failed tests: ' + ','.join(failed) if failed else 'no failed test'}"
            "; not an assertion failure)"), []


def test_tags() -> dict[str, set[str]]:
    spec = importlib.util.spec_from_file_location("traceability", HERE / "traceability.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["traceability"] = mod
    spec.loader.exec_module(mod)
    return mod.parse_tests()


@dataclass(frozen=True)
class Mutant:
    name: str
    invariant: str
    old: str
    new: str
    file: str = "conformance_suite.py"     # the module the patch applies to


MUTANTS = [
    # I1: the last departure does not record the resume point
    Mutant("I1-no-resume-prepared", "I1",
           """            (GE.DETACHMENT, {"reason": reason}),
            self._prepared_item(s, reason)])""",
           """            (GE.DETACHMENT, {"reason": reason})])"""),
    # I2: tool calls are forwarded while a human is pending
    Mutant("I2-forward-while-pending", "I2",
           "        if s.human == Human.PENDING:\n            if key is None:",
           "        if s.human == Human.PENDING and False:\n            if key is None:"),
    # I3: widening accepted when detached; narrowing accepts widening;
    # an observed widening is recorded as granted or not reverted
    Mutant("I3-accept-widening-detached", "I3",
           """        if set(new_scope).issubset(s.scope):
            return None
        if source == "observed":""",
           """        if (set(new_scope).issubset(s.scope)
                or s.att != Attachment.ATTACHED):
            return None
        if source == "observed":"""),
    Mutant("I3-narrow-accepts-widening", "I3",
           """        if not proposed.issubset(current):
            self._reject_extension(sid, s, new_scope, "refused")
        if proposed == current:""",
           """        if proposed == current:"""),
    Mutant("I3-observed-widening-recorded", "I3",
           """            self.revert_requests.append((sid, s.scope))""",
           """            s.scope = tuple(new_scope)
            self.revert_requests.append((sid, s.scope))"""),
    Mutant("I3-observed-widening-not-reverted", "I3",
           '''            self.revert_requests.append((sid, s.scope))
            return "REVERT"''',
           '''            return "REVERT"'''),
    # I4: the presented history is not checked against the chain; the
    # replay is empty or starts at the wrong event
    Mutant("I4-no-prefix-check", "I4",
           "        if not (0 <= req.seq < len(log)) or log[req.seq].event_hash() != req.hash:",
           "        if False:"),
    Mutant("I4-no-replay", "I4",
           "        return list(self.storage.logs[sid][seq + 1:])",
           "        return []"),
    Mutant("I4-replay-off-by-one", "I4",
           "        return list(self.storage.logs[sid][seq + 1:])",
           "        return list(self.storage.logs[sid][seq + 2:])"),
    # I5: events are no longer chained to their predecessor
    Mutant("I5-no-prev-hash", "I5",
           "            ev = Event(kind, sid, seq, prev, payload, ts)",
           "            ev = Event(kind, sid, seq, \"\", payload, ts)"),
    # I6: a terminated session accepts operations
    Mutant("I6-ops-after-termination", "I6",
           """        s = self._sess[sid]
        if s.life == Lifecycle.TERMINATED:
            raise BridgeError("session is TERMINATED (I6)", reason="terminated")
        if s.quarantined:
            raise BridgeError("session is QUARANTINED", reason="quarantined")
        if s.key_exhausted and not exhausted_ok:
            self._check_timers(sid)
            if s.life == Lifecycle.TERMINATED:
                raise BridgeError("session is TERMINATED (I6)", reason="terminated")
            raise BridgeError("session is KEY_EXHAUSTED", reason="key_exhausted")
        self._check_timers(sid)
        if s.life == Lifecycle.TERMINATED:
            raise BridgeError("session is TERMINATED (I6)", reason="terminated")
        return s""",
           """        s = self._sess[sid]
        if s.quarantined:
            raise BridgeError("session is QUARANTINED", reason="quarantined")
        self._check_timers(sid)
        return s"""),
    # I7: the cell changes before the events are appended
    Mutant("I7-mutate-before-append", "I7",
           """        self.storage.append_batch(sid, batch)       # I12 / I7: durable first
        for ev in batch:
            self._apply(ev)""",
           """        for ev in batch:
            self._apply(ev)
        self.storage.append_batch(sid, batch)"""),
    # I8: a reported 0-RTT replay is ignored
    Mutant("I8-ignore-replay", "I8",
           "        if transport_replay:\n            return \"transport_replay\"",
           "        if False:\n            return \"transport_replay\""),
    # I9: nonce lifetime
    Mutant("I9-ignore-expiry", "I9",
           "        if self._now() - issued >= self.cfg.t_nonce:          # I9",
           "        if False:"),
    Mutant("I9-expiry-terminates", "I9",
           '''        if self._now() - issued >= self.cfg.t_nonce:          # I9
            return "nonce_expired"''',
           '''        if self._now() - issued >= self.cfg.t_nonce:          # I9
            self._commit(sid, [(GE.TERMINATION, {"reason": "nonce_expired"})])
            return "nonce_expired"'''),
    # I10: the scope version does not advance; a no-op narrowing is accepted
    Mutant("I10-version-not-incremented", "I10",
           "        version = s.scope_version + 1",
           "        version = s.scope_version"),
    Mutant("I10-noop-narrowing-accepted", "I10",
           """        if proposed == current:
            self._commit(sid, [(GE.AUTHORITY_NARROWING_REJECTED""",
           """        if False:
            self._commit(sid, [(GE.AUTHORITY_NARROWING_REJECTED"""),
    # I11: proof of possession, single use, session binding, no state change
    Mutant("I11-drop-proof-check", "I11",
           """        if public is None or not _verify_scheme(
                scheme, public,
                _resume_bytes(op, sid, req.key_id, req.nonce, req.seq,
                              req.hash),
                req.signature):""",
           "        if False:"),
    # the re-attach/join proof binds the operation tag and the key id
    Mutant("I11-resume-domain-tag-dropped", "I11",
           "    return _canon([RESUME_DOMAINS[op], sid, key_id, nonce, seq, hash_])",
           "    return _canon([sid, key_id, nonce, seq, hash_])"),
    Mutant("I11-resume-key-id-dropped", "I11",
           "    return _canon([RESUME_DOMAINS[op], sid, key_id, nonce, seq, hash_])",
           "    return _canon([RESUME_DOMAINS[op], sid, nonce, seq, hash_])"),
    Mutant("I11-resume-operation-ignored", "I11",
           "                _resume_bytes(op, sid, req.key_id, req.nonce, req.seq,",
           "                _resume_bytes(\"reattach\", sid, req.key_id, req.nonce, req.seq,"),
    Mutant("I11-join-tagged-as-reattach", "I11",
           '"join": "bc/v1/join"}\n\n\ndef _resume_bytes',
           '"join": "bc/v1/reattach"}\n\n\ndef _resume_bytes'),
    Mutant("I11-scheme-tag-ignored", "I11",
           """        if public is None or not _verify_scheme(
                scheme, public,
                _resume_bytes(""",
           """        if public is None or not _verify_scheme(
                SCHEME_ED25519, public,
                _resume_bytes("""),
    Mutant("I11-nonce-not-single-use", "I11",
           "        rec[1] = True                                              # I11d",
           "        pass"),
    Mutant("I11-nonce-spent-only-on-success", "I11",
           """        rec[1] = True                                              # I11d
        if used:""",
           """        if used:"""),
    Mutant("I11-unauthentic-request-spends-nonce", "I11",
           """        record = self.storage.key_record(sid, req.key_id)
        scheme, public = record if record else (SCHEME_ED25519, None)
        if public is None""",
           """        self._nonces.get(sid, {}).get(req.nonce, [0, 0])[1] = True
        record = self.storage.key_record(sid, req.key_id)
        scheme, public = record if record else (SCHEME_ED25519, None)
        if public is None"""),
    Mutant("I11-registry-stores-signing-seed", "I11",
           "        self.storage.register_key(sid, client_key.key_id, client_key.scheme,\n                                  client_key.public_key)",
           "        self.storage.register_key(sid, client_key.key_id, client_key.scheme,\n                                  client_key.seed)"),
    Mutant("I11-added-key-registry-stores-signing-seed", "I11",
           "        self.storage.register_key(sid, new_key.key_id, new_key.scheme,\n                                  new_key.public_key)",
           "        self.storage.register_key(sid, new_key.key_id, new_key.scheme,\n                                  new_key.seed)"),
    Mutant("I11-nonce-not-bound-to-session", "I11",
           "        rec = self._nonces.get(sid, {}).get(req.nonce)",
           "        rec = next((b[req.nonce] for b in self._nonces.values()\n                    if req.nonce in b), None)"),
    Mutant("I11-bad-reattach-terminates", "I11",
           """            self._commit(sid, [(GE.RESUME_REJECTED, {
                "reason": reason, "key_id": req.key_id, "seq": req.seq})])""",
           """            self._commit(sid, [(GE.RESUME_REJECTED, {
                "reason": reason, "key_id": req.key_id, "seq": req.seq}),
                (GE.TERMINATION, {"reason": "resume_fail"})])"""),
    # I12: forwarding before the drain events are durable; recovery
    Mutant("I12-forward-before-commit", "I12",
           """            batch = self._commit(sid, items)
            for ev in batch:                              # I12: after commit
                if ev.kind == GE.TOOL_CALL_DRAINED:
                    self._send(sid, ev.payload["key"], ev.payload["tool"],
                               ev.payload["permission"],
                               ev.payload["content"])""",
           """            for kind, p in items:
                if kind == GE.TOOL_CALL_DRAINED:
                    self._send(sid, p["key"], p["tool"], p["permission"],
                               p["content"])
            self._commit(sid, items)"""),
    Mutant("I12-recovery-skips-replay", "I12",
           """                for ev in log:                     # replay: log determines cell
                    b._apply(ev)""",
           """                b._apply(log[0])
                for ev in []:
                    pass"""),
    # I13: queue limit, duplicates, approval freshness, scope revalidation
    Mutant("I13-no-queue-limit", "I13",
           "            if len(s.queue) >= self.cfg.q_max:",
           "            if False:"),
    Mutant("I13-duplicate-keys-queued", "I13",
           "            if key in s.used_keys:\n                return \"DUPLICATE\"",
           "            if False:\n                return \"DUPLICATE\""),
    Mutant("I13-no-approval-expiry", "I13",
           '            elif now >= s.approval_until and not c["held"]:',
           "            elif False:"),
    Mutant("I13-no-scope-revalidation", "I13",
           """            elif c["permission"] is not None and c["permission"] not in s.scope:""",
           """            elif False:"""),
    Mutant("I13-no-call-expiry", "I13",
           """                for c in s.queue if now >= c["expires_at"]]""",
           """                for c in s.queue if False]"""),
    # I14: answer binding
    Mutant("I14-hash-equality-not-checked", "I14",
           """            elif c["answer"][1] != c["shown_hash"]:""",
           """            elif False:"""),
    Mutant("I14-unanswered-call-drained", "I14",
           """                items.append((GE.TOOL_CALL_REJECTED,
                              {**base, "reason": "unanswered"}))""",
           """                items.append((GE.TOOL_CALL_DRAINED,
                              {**base, "authority_hash": ah,
                               "shown_hash": c["shown_hash"]}))"""),
    Mutant("I14-denial-ignored", "I14",
           """            elif c["answer"][0] != "approve":""",
           """            elif False:"""),
    Mutant("I14-second-answer-accepted", "I14",
           """        if entry["answer"] is not None:
            raise BridgeError("call already answered (I14)")""",
           """        if False:
            raise BridgeError("call already answered (I14)")"""),
    Mutant("I14-shown-hash-not-of-content", "I14",
           """            "shown_hash": call_hash(tool, permission, content), "held": True,""",
           """            "shown_hash": content_hash(tool), "held": True,"""),
    Mutant("I14-drained-omits-hash", "I14",
           """                              {**base, **sent, "authority_hash": ah,
                               "shown_hash": c["shown_hash"]}))
        if items:""",
           """                              {**base, **sent, "authority_hash": ah}))
        if items:"""),
    Mutant("I14-hash-omits-tool-and-permission", "I14",
           """                "content": content,
                "shown_hash": call_hash(tool, permission, content),
                "expires_at\"""",
           """                "content": content,
                "shown_hash": content_hash(content),
                "expires_at\""""),
    Mutant("I14-forwards-without-hashed-content", "I14",
           """                               ev.payload["permission"],
                               ev.payload["content"])""",
           """                               ev.payload["permission"],
                               None)"""),
    Mutant("I14-queued-content-not-retained", "I14",
           """                            "content": p.get("content"),""",
           """                            "content": None,"""),
    # I15: client set
    Mutant("I15-partial-departure-detaches", "I15",
           """        remaining = (set(s.conn) - targets
                     if s.att == Attachment.ATTACHED else set())""",
           """        remaining = set()"""),
    Mutant("I15-unregistered-key-accepted", "I15",
           '''        if req.key_id not in s.keys:
            return "unknown_key"''',
           '''        if False:
            return "unknown_key"'''),
    Mutant("I15-registration-needs-no-client", "I15",
           "        if via_key_id not in s.conn:",
           "        if False:"),
    Mutant("I15-add-client-skip-verify", "I15",
           """            raise AddClientRejected("bad_signature")""",
           """            pass"""),
    Mutant("I15-add-client-nonce-not-spent", "I15",
           """        rec[1] = True                                  # spent, as in I11d""",
           """        pass"""),
    Mutant("I15-add-client-domain-tag-dropped", "I15",
           """    return _canon([ADD_CLIENT_DOMAIN, sid, via_key_id, new_key_id, scheme,
                   public_key, nonce])""",
           """    return _canon([sid, via_key_id, new_key_id, scheme,
                   public_key, nonce])"""),
    Mutant("I15-add-client-public-key-unbound", "I15",
           """    return _canon([ADD_CLIENT_DOMAIN, sid, via_key_id, new_key_id, scheme,
                   public_key, nonce])""",
           """    return _canon([ADD_CLIENT_DOMAIN, sid, via_key_id, new_key_id,
                   nonce])"""),
    Mutant("I15-add-client-revoked-key-authorises", "I15",
           """        if via_key_id in s.revoked_keys:
            raise AddClientRejected("revoked_key")""",
           """        if False:
            raise AddClientRejected("revoked_key")"""),
    Mutant("I15-join-does-not-add-client", "I15",
           """            s.conn.add(p["key_id"])""",
           """            pass"""),
    Mutant("I15-resume-attaches-nobody", "I15",
           """            s.conn = {s.resuming} if s.resuming else set()""",
           """            s.conn = set()"""),
    Mutant("I15-added-key-not-registered", "I15",
           """        if k == GE.CLIENT_ADDED:
            s.keys.add(p["key_id"])""",
           """        if k == GE.CLIENT_ADDED:
            pass"""),
    # Timer bounds, cumulative detachment cap
    Mutant("TIMERS-bound-not-enforced", "TIMERS",
           "        if not self.t_call <= self.t_human:",
           "        if False:"),
    Mutant("TIMERS-cap-bound-not-enforced", "TIMERS",
           "        if not self.t_detach <= self.t_total:",
           "        if False:"),
    Mutant("TIMERS-cap-forgets-closed-episodes", "TIMERS",
           "                s.det_total += ev.timestamp - s.det_since",
           "                pass"),
    Mutant("TIMERS-cap-restarts-with-a-restart", "TIMERS",
           """            if s.att != Attachment.DETACHED:        # a restart while away
                s.det_since = ev.timestamp          # continues the interval""",
           """            s.det_since = ev.timestamp"""),
    Mutant("TIMERS-cap-counts-time-resuming", "TIMERS",
           """                s.det_total += ev.timestamp - s.det_since
                s.det_since = None""",
           """                s.det_total += ev.timestamp - s.det_since"""),
    Mutant("TIMERS-cap-disabled", "TIMERS",
           "                 and s.det_total + (now - s.det_since) >= self.cfg.t_total)",
           "                 and False)"),
    # I5: a chain failure freezes the session; it does not end it, and a
    # frozen session accepts nothing
    Mutant("I5-resume-failure-terminates", "I5",
           """            self._quarantine(sid, GE.RESUME_FAILED, {"reason": "chain"})
            raise""",
           """            self._quarantine(sid, GE.RESUME_FAILED, {"reason": "chain"})
            self.terminate(sid, "resume_fail")
            raise"""),
    Mutant("I5-recovery-failure-terminates", "I5",
           """                b._quarantine(sid, GE.RECOVERY_FAILED, {"reason": str(exc)})
                continue""",
           """                b._quarantine(sid, GE.RECOVERY_FAILED, {"reason": str(exc)})
                b.terminate(sid, "recovery_fail")
                continue"""),
    Mutant("I5-quarantined-session-still-served", "I5",
           """        if s.quarantined:
            raise BridgeError("session is QUARANTINED", reason="quarantined")
        if s.key_exhausted and not exhausted_ok:
            self._check_timers(sid)
            if s.life == Lifecycle.TERMINATED:
                raise BridgeError("session is TERMINATED (I6)", reason="terminated")
            raise BridgeError("session is KEY_EXHAUSTED", reason="key_exhausted")
        self._check_timers(sid)""",
           """        self._check_timers(sid)"""),
    Mutant("I5-quarantine-not-durable", "I5",
           """        elif k in (GE.RESUME_FAILED, GE.RECOVERY_FAILED):
            s.quarantined = True""",
           """        elif k == GE.RECOVERY_FAILED:
            s.quarantined = True"""),
    # G1 variants and the forwarding acknowledgement
    Mutant("I2-detached-call-forwarded-by-default", "I2",
           """        if policy == "refuse" or not in_scope or (""",
           """        if not in_scope or (""") ,
    Mutant("I2-forward-policy-ignores-allowlist", "D",
           """                policy == "forward"
                and permission not in self.cfg.detached_allow):""",
           """                False):"""),
    Mutant("I14-held-call-forwarded-unanswered", "I14",
           """            if c["held"] and c["answer"] is None and now < c["expires_at"]:
                continue                  # waits for its answer (G1 variant)""",
           """            if False:
                continue"""),
    Mutant("I12-unacknowledged-call-not-forwarded-again", "D",
           """            if (sid, key) not in self._sent:
                self._send(sid, key, call["tool"], call["permission"],
                           call["content"])""",
           """            pass"""),
    Mutant("I13-acknowledged-call-forwarded-again", "I13",
           """        elif k == GE.TOOL_CALL_DELIVERED:
            s.unacked.pop(p["key"], None)""",
           """        elif k == GE.TOOL_CALL_DELIVERED:
            pass"""),
    # Liveness and rule D (timers, drain)
    Mutant("L1-detach-timer-restarts-on-escalation", "L1",
           """        elif k == GE.HUMAN_PENDING:
            if s.human == Human.NONE:""",
           """        elif k == GE.HUMAN_PENDING:
            if s.att == Attachment.DETACHED:
                s.detach_at = ev.timestamp
            if s.human == Human.NONE:"""),
    Mutant("L2-human-timeout-disabled", "I6",
           "        human = (s.human == Human.PENDING and s.human_at is not None",
           "        human = (False and s.human_at is not None"),
    Mutant("RuleD-drain-while-detached", "D",
           """        if not (s.att == Attachment.ATTACHED and s.human == Human.NONE
                and s.life""",
           """        if not (s.human == Human.NONE
                and s.life"""),
    # I-CHECKPOINT mutants
    Mutant("ICHECK-drop-checkpoint-emission", "ICHECK",
           "        if not _checkpoint:\n            self._maybe_checkpoint(sid)",
           "        if not _checkpoint:\n            pass"),
    Mutant("ICHECK-wrong-root", "ICHECK",
           '        root = merkle_root(hashes).hex()',
           '        root = "00" * 32'),
    Mutant("ICHECK-count-trigger-total-length", "ICHECK",
           "        since = n - self._cp_len.get(sid, 0)    # events since the last checkpoint",
           "        since = n"),
    Mutant("ICHECK-missed-deadline", "ICHECK",
           "        if since < self.cfg.n_checkpoint and (now - last) < self.cfg.t_checkpoint:",
           "        if since < self.cfg.n_checkpoint and (now - last) < self.cfg.t_checkpoint * 1000:"),
    # I-GRANT mutants (authorisation boundary)
    Mutant("IGRANT-skip-verify", "I-GRANT",
           "        if self.grant_verifier is None or not self.grant_verifier(\n                session, client_key, grant, self.bridge_id):\n            raise GrantInvalid(",
           "        if False:\n            raise GrantInvalid("),
    Mutant("IGRANT-no-verifier-accepts", "I-GRANT",
           "        if self.grant_verifier is None or not self.grant_verifier(\n                session, client_key, grant, self.bridge_id):",
           "        if self.grant_verifier is not None and not self.grant_verifier(\n                session, client_key, grant, self.bridge_id):"),
    Mutant("IGRANT-grant-not-bound-to-scope", "I-GRANT",
           "    return [bridge_id, session.session_id, session.principal_id,\n            list(session.authority_scope), list(session.task_lineage),",
           "    return [bridge_id, session.session_id, session.principal_id,\n            [], list(session.task_lineage),"),
    Mutant("IGRANT-grant-omits-public-key", "I-GRANT",
           "    return _canon([GRANT_DOMAIN] + _attach_fields(bridge_id, session, key))",
           "    return _canon([GRANT_DOMAIN] + _attach_fields(bridge_id, session, key)[:-2])"),
    Mutant("IGRANT-grant-omits-bridge-id", "I-GRANT",
           "    return _canon([GRANT_DOMAIN] + _attach_fields(bridge_id, session, key))",
           "    return _canon([GRANT_DOMAIN] + _attach_fields(bridge_id, session, key)[1:])"),
    Mutant("IGRANT-attach-skip-possession", "I-GRANT",
           "        if not isinstance(proof, str) or not _verify_scheme(\n                client_key.scheme, client_key.public_key,\n                _attach_bytes(self.bridge_id, session, client_key), proof):",
           "        if False:"),
    Mutant("IGRANT-possession-omits-bridge-id", "I-GRANT",
           "    return _canon([ATTACH_DOMAIN] + _attach_fields(bridge_id, session, key))",
           "    return _canon([ATTACH_DOMAIN] + _attach_fields(bridge_id, session, key)[1:])"),
    Mutant("IGRANT-possession-uses-grant-domain", "I-GRANT",
           'ATTACH_DOMAIN = "bc/v1/attach"', 'ATTACH_DOMAIN = "bc/v1/grant"'),
    Mutant("IGRANT-possession-omits-public-key", "I-GRANT",
           "    return _canon([ATTACH_DOMAIN] + _attach_fields(bridge_id, session, key))",
           "    return _canon([ATTACH_DOMAIN] + _attach_fields(bridge_id, session, key)[:-2])"),
    # B1: the key registry is scoped to a session
    Mutant("registry-global-by-key-id", "I11",
           "        return (sid, key_id)\n\n    def register_key(self, sid: str, key_id: str, scheme: str,\n                     public_key: bytes) -> None:\n        \"\"\"Record a client key for one session.  A key id already\n        registered in the session is refused, never replaced.\"\"\"\n        slot = self._slot(sid, key_id)\n        if slot in self.client_keys:\n            raise BridgeError(f\"key id {key_id!r} already registered in \"\n                              f\"the session\", reason=\"key_already_registered\")\n",
           "        return key_id\n\n    def register_key(self, sid: str, key_id: str, scheme: str,\n                     public_key: bytes) -> None:\n        slot = self._slot(sid, key_id)\n"),
    Mutant("registry-reregistration-allowed", "I11",
           "        if slot in self.client_keys:\n            raise BridgeError(f\"key id {key_id!r} already registered in \"",
           "        if False:\n            raise BridgeError(f\"key id {key_id!r} already registered in \""),
    # M1: the registry is rebuilt from the log and compared
    Mutant("registry-recovery-leaves-differing-entries", "I11",
           "            if self.storage.key_record(sid, kid) != want:\n                self.storage.unregister_key(sid, kid)\n                self.storage.register_key(sid, kid, scheme, want[1])\n                repaired.add(kid)",
           "            if self.storage.key_record(sid, kid) is None:\n                self.storage.unregister_key(sid, kid)\n                self.storage.register_key(sid, kid, scheme, want[1])\n                repaired.add(kid)"),
    Mutant("registry-recovery-leaves-extra-entries", "I11",
           "        for kid in self.storage.registered_key_ids(sid) - s.keys:\n            self.storage.unregister_key(sid, kid)\n            repaired.add(kid)\n",
           ""),
    Mutant("registry-recovery-leaves-missing-entries", "I11",
           "            if self.storage.key_record(sid, kid) != want:\n                self.storage.unregister_key(sid, kid)\n                self.storage.register_key(sid, kid, scheme, want[1])\n                repaired.add(kid)",
           "            if self.storage.key_record(sid, kid) not in (None, want):\n                self.storage.unregister_key(sid, kid)\n                self.storage.register_key(sid, kid, scheme, want[1])\n                repaired.add(kid)"),
    Mutant("registry-recovery-repair-unreported", "I11",
           '(GE.BRIDGE_RECOVERED, {"events": len(log),\n                                       "registry_repaired": repaired}),',
           '(GE.BRIDGE_RECOVERED, {"events": len(log),\n                                       "registry_repaired": []}),'),
    Mutant("registry-recovery-repairs-a-broken-chain-session", "I11",
           "            try:\n                b._verify_event_chain(sid)\n            except Exception as exc:               # BridgeError or malformed\n                b._quarantine(sid, GE.RECOVERY_FAILED, {\"reason\": str(exc)})\n                continue\n            repaired = b._repair_registry(sid, s)",
           "            repaired = b._repair_registry(sid, s)\n            try:\n                b._verify_event_chain(sid)\n            except Exception as exc:               # BridgeError or malformed\n                b._quarantine(sid, GE.RECOVERY_FAILED, {\"reason\": str(exc)})\n                continue"),
    Mutant("registry-client-added-logs-wrong-key", "I11",
           '                "public_key": new_key.public_key.hex()})])',
           '                "public_key": new_key.key_id.encode().hex()})])'),
    Mutant("registry-attached-logs-no-scheme", "I11",
           '                "scheme": client_key.scheme,\n                "public_key": client_key.public_key.hex(),',
           '                "scheme": SCHEME_ED25519,\n                "public_key": client_key.public_key.hex(),'),
    Mutant("registry-failed-attach-keeps-entry", "I11",
           "        except StorageError:\n            self.storage.unregister_key(sid, client_key.key_id)\n            raise",
           "        except StorageError:\n            raise"),
    # state a bridge keeps per session is not shared between sessions
    Mutant("session-nonce-book-shared", "I11",
           "        self._nonces: dict[str, dict[str, list]] = {}",
           "        self._nonces = type(\"OneBook\", (dict,), {\n"
           "            \"get\": lambda s, k, d=None: dict.get(s, \"\", d),\n"
           "            \"setdefault\": lambda s, k, d=None: dict.setdefault(s, \"\", d),\n"
           "            \"__getitem__\": lambda s, k: dict.__getitem__(s, \"\")})()"),
    Mutant("session-unauth-budget-shared", "I11g",
           "            logged = self._unauth_logged.get(sid, 0)",
           "            logged = sum(self._unauth_logged.values())"),
    Mutant("session-unauth-budget-restored-for-all", "I11g",
           "            self._unauth_logged.pop(sid, None)      # a key holder spoke",
           "            self._unauth_logged.clear()             # a key holder spoke"),
    Mutant("session-revocation-requests-shared", "I11-REVOKE",
           "            asked = self._revocation_requests.get(sid, 0)",
           "            asked = sum(self._revocation_requests.values())"),
    Mutant("session-revocation-requests-restored-for-all", "I11-REVOKE",
           "            self._revocation_requests.pop(sid, None)",
           "            self._revocation_requests.clear()"),
    Mutant("session-forwarded-key-shared", "D",
           "            if (sid, key) not in self._sent:",
           "            if key not in {k for _, k in self._sent}:"),
    # I11-REVOKE: key lifecycle
    Mutant("I11-REVOKE-accept-revoked-key", "I11-REVOKE",
           "        if req.key_id in s.revoked_keys:",
           "        if False:"),
    Mutant("I11-REVOKE-revoked-request-keeps-nonce", "I11-REVOKE",
           "                spent[1] = True                                    # request",
           "                pass"),
    Mutant("I11-REVOKE-soft-detaches", "I11-REVOKE",
           '            if reason == "compromise" and (\n',
           '            if reason in ("compromise", "rotation") and (\n'),
    Mutant("I11-REVOKE-hard-res-not-abandoned", "I11-REVOKE",
           '                    or (s.att == Attachment.RESUMING\n                        and s.resuming == key_id)):',
           '                    ):'),
    Mutant("I11-REVOKE-soft-leaves-client-set", "I11-REVOKE",
           '            if p["reason"] == "compromise":                 # hard: leaves C(s)',
           '            if p["reason"] in ("compromise", "rotation"):   # hard: leaves C(s)'),
    Mutant("I11-REVOKE-hard-keeps-client-set", "I11-REVOKE",
           '            if p["reason"] == "compromise":                 # hard: leaves C(s)',
           '            if False:                                       # hard: leaves C(s)'),
    Mutant("I11-REVOKE-key-exhausted-not-blocked", "I11-REVOKE",
           "        if s.key_exhausted and not exhausted_ok:\n",
           "        if s.key_exhausted and not exhausted_ok and False:\n"),
    # key_exhausted keeps its timers (L1, L2)
    Mutant("TIMERS-key-exhausted-timers-frozen", "I11-REVOKE",
           "        if s.life == Lifecycle.TERMINATED or s.quarantined:\n            return\n        now = self._now()",
           "        if (s.life == Lifecycle.TERMINATED or s.quarantined\n                or s.key_exhausted):\n            return\n        now = self._now()"),
    Mutant("I11-REVOKE-key-exhausted-restart-skipped", "I11-REVOKE",
           "            if s.life == Lifecycle.TERMINATED or s.quarantined:\n                continue",
           "            if (s.life == Lifecycle.TERMINATED or s.quarantined\n                    or s.key_exhausted):\n                continue"),
    Mutant("I11-REVOKE-key-exhausted-refused-before-timers", "I11-REVOKE",
           "            self._check_timers(sid)\n            if s.life == Lifecycle.TERMINATED:\n                raise BridgeError(\"session is TERMINATED (I6)\", reason=\"terminated\")\n            raise BridgeError(\"session is KEY_EXHAUSTED\", reason=\"key_exhausted\")",
           "            raise BridgeError(\"session is KEY_EXHAUSTED\", reason=\"key_exhausted\")"),
    Mutant("I11-REVOKE-key-exhausted-disconnect-refused", "I11-REVOKE",
           "        s = self._enter(sid, exhausted_ok=True)",
           "        s = self._enter(sid)"),
    Mutant("I11-REVOKE-add-key-after-expiry", "I11-REVOKE",
           "        self._check_timers(sid)          # an expired session is over (L1)\n",
           ""),
    Mutant("I11-REVOKE-exhaustion-not-derived", "I11-REVOKE",
           '                s.conn.discard(p["key_id"])\n            s.key_exhausted = not (s.keys - s.revoked_keys)',
           '                s.conn.discard(p["key_id"])\n            s.key_exhausted = False'),
    Mutant("I11-REVOKE-add-key-not-replayed", "I11-REVOKE",
           '            s.keys.add(p["key_id"])\n            s.key_material[p["key_id"]] = (p["scheme"], p["public_key"])\n            s.key_exhausted = not (s.keys - s.revoked_keys)\n        elif k == GE.CLIENT_JOINED:',
           '            s.key_exhausted = not (s.keys - s.revoked_keys)\n        elif k == GE.CLIENT_JOINED:'),
    Mutant("I11-REVOKE-add-key-readmits-registered-id", "I11-REVOKE",
           '        if key_id in s.keys:\n            raise BridgeError("client key already registered",\n                              reason="key_already_registered")\n        self._operator_verified(',
           '        self._operator_verified('),
    Mutant("I11-REVOKE-add-key-outside-exhaustion", "I11-REVOKE",
           '        if not s.key_exhausted:\n            raise BridgeError("session is not key_exhausted",\n                              reason="not_key_exhausted")\n        if key_id in s.keys:',
           '        if key_id in s.keys:'),
    Mutant("I11-REVOKE-added-key-not-registered", "I11-REVOKE",
           "        self.storage.register_key(sid, key_id, scheme,\n                                  bytes.fromhex(public_key))\n",
           "        pass\n"),
    Mutant("I11-REVOKE-terminate-outside-exhaustion", "I11-REVOKE",
           '        if not s.key_exhausted:\n            raise BridgeError("session is not key_exhausted",\n                              reason="not_key_exhausted")\n        self._operator_verified(\n            lambda b, q, h: _terminate_bytes(b, sid, reason, q, h),\n            signature, sid)\n        self._commit(sid, [(GE.OPERATOR_TERMINATION',
           '        self._operator_verified(\n            lambda b, q, h: _terminate_bytes(b, sid, reason, q, h),\n            signature, sid)\n        self._commit(sid, [(GE.OPERATOR_TERMINATION'),
    Mutant("I11-REVOKE-unknown-key-revocable", "I11-REVOKE",
           '        if key_id not in s.keys:\n            raise BridgeError(f"unknown key {key_id!r}", reason="unknown_key")',
           '        pass'),
    Mutant("I11-REVOKE-request-executes-revocation", "I11-REVOKE",
           "        if signature != \"\":\n            payload = {",
           "        if signature != \"\" or requested_by:\n            payload = {"),
    # I-OPERATOR: operator events are authenticated
    Mutant("IOPERATOR-revoke-skip-verify", "I-OPERATOR",
           '        if signature != "" or requested_by is None:\n            self._operator_verified(\n                lambda b, q, h: _revoke_bytes(b, sid, key_id, reason, q, h),\n                signature, sid)\n',
           ''),
    Mutant("IOPERATOR-add-key-skip-verify", "I-OPERATOR",
           '        self._operator_verified(\n            lambda b, q, h: _add_key_bytes(b, sid, key_id, scheme,\n                                           public_key, q, h),\n            signature, sid)\n',
           ''),
    Mutant("IOPERATOR-terminate-skip-verify", "I-OPERATOR",
           '        self._operator_verified(\n            lambda b, q, h: _terminate_bytes(b, sid, reason, q, h),\n            signature, sid)\n',
           ''),
    Mutant("IOPERATOR-no-verifier-accepts", "I-OPERATOR",
           "        if check is None or not check(message, signature):",
           "        if check is not None and not check(message, signature):"),
    Mutant("IOPERATOR-missing-signature-accepted", "I-OPERATOR",
           "        if not isinstance(signature, str):\n            return False\n        return _verify(self.operator_public_key, message, signature)",
           "        if not isinstance(signature, str):\n            return True\n        return _verify(self.operator_public_key, message, signature)"),
    Mutant("IOPERATOR-revoke-not-bound-to-reason", "I-OPERATOR",
           "    return _canon([REVOKE_DOMAIN, bridge_id, sid, key_id, reason, seq, head])",
           "    return _canon([REVOKE_DOMAIN, bridge_id, sid, key_id, seq, head])"),
    Mutant("IOPERATOR-revoke-not-bound-to-key", "I-OPERATOR",
           "    return _canon([REVOKE_DOMAIN, bridge_id, sid, key_id, reason, seq, head])",
           "    return _canon([REVOKE_DOMAIN, bridge_id, sid, reason, seq, head])"),
    Mutant("IOPERATOR-add-key-not-bound-to-key-material", "I-OPERATOR",
           "    return _canon([ADD_KEY_DOMAIN, bridge_id, sid, key_id, scheme,\n                   public_key, seq, head])",
           "    return _canon([ADD_KEY_DOMAIN, bridge_id, sid, key_id, scheme,\n                   seq, head])"),
    Mutant("IOPERATOR-terminate-not-bound-to-session", "I-OPERATOR",
           "    return _canon([TERMINATE_DOMAIN, bridge_id, sid, reason, seq, head])",
           "    return _canon([TERMINATE_DOMAIN, bridge_id, reason, seq, head])"),
    Mutant("IOPERATOR-revoke-not-bound-to-bridge", "I-OPERATOR",
           "    return _canon([REVOKE_DOMAIN, bridge_id, sid, key_id, reason, seq, head])",
           "    return _canon([REVOKE_DOMAIN, sid, key_id, reason, seq, head])"),
    Mutant("IOPERATOR-add-key-not-bound-to-bridge", "I-OPERATOR",
           "    return _canon([ADD_KEY_DOMAIN, bridge_id, sid, key_id, scheme,\n                   public_key, seq, head])",
           "    return _canon([ADD_KEY_DOMAIN, sid, key_id, scheme,\n                   public_key, seq, head])"),
    Mutant("IOPERATOR-terminate-not-bound-to-bridge", "I-OPERATOR",
           "    return _canon([TERMINATE_DOMAIN, bridge_id, sid, reason, seq, head])",
           "    return _canon([TERMINATE_DOMAIN, sid, reason, seq, head])"),
    Mutant("IOPERATOR-revoke-not-bound-to-position", "I-OPERATOR",
           "    return _canon([REVOKE_DOMAIN, bridge_id, sid, key_id, reason, seq, head])",
           "    return _canon([REVOKE_DOMAIN, bridge_id, sid, key_id, reason])"),
    Mutant("IOPERATOR-add-key-not-bound-to-position", "I-OPERATOR",
           "    return _canon([ADD_KEY_DOMAIN, bridge_id, sid, key_id, scheme,\n                   public_key, seq, head])",
           "    return _canon([ADD_KEY_DOMAIN, bridge_id, sid, key_id, scheme,\n                   public_key])"),
    Mutant("IOPERATOR-terminate-not-bound-to-position", "I-OPERATOR",
           "    return _canon([TERMINATE_DOMAIN, bridge_id, sid, reason, seq, head])",
           "    return _canon([TERMINATE_DOMAIN, bridge_id, sid, reason])"),
    Mutant("IOPERATOR-revoke-binds-sequence-only", "I-OPERATOR",
           "    return _canon([REVOKE_DOMAIN, bridge_id, sid, key_id, reason, seq, head])",
           "    return _canon([REVOKE_DOMAIN, bridge_id, sid, key_id, reason, seq])"),
    Mutant("IOPERATOR-revoke-binds-hash-only", "I-OPERATOR",
           "    return _canon([REVOKE_DOMAIN, bridge_id, sid, key_id, reason, seq, head])",
           "    return _canon([REVOKE_DOMAIN, bridge_id, sid, key_id, reason, head])"),
    # a re-attach on an attached session is refused; join is the way in
    Mutant("I11-reattach-on-attached-session-joins", "I11",
           '        if (reason is None and s.att == Attachment.ATTACHED\n                and op == "reattach"):\n            reason = "already_attached"',
           '        if False:\n            reason = "already_attached"'),
    Mutant("I11-already-attached-before-authentication", "I11",
           '        reason = self._reject_reason(sid, s, req, transport_replay, op)\n        if reason is None and s.att == Attachment.RESUMING:',
           '        reason = self._reject_reason(sid, s, req, transport_replay, op)\n        if s.att == Attachment.ATTACHED and op == "reattach":\n            reason = "already_attached"\n        if reason is None and s.att == Attachment.RESUMING:'),
    Mutant("I11-join-refused-as-already-attached", "I11",
           '        if (reason is None and s.att == Attachment.ATTACHED\n                and op == "reattach"):',
           '        if (reason is None and s.att == Attachment.ATTACHED):'),
    Mutant("IOPERATOR-domain-tags-collide", "I-OPERATOR",
           'TERMINATE_DOMAIN = "bc/v1/terminate"',
           'TERMINATE_DOMAIN = "bc/v1/revoke"'),
    # I11: the server takes a client's public key, never a signing key
    Mutant("I11-attach-accepts-signing-key", "I11",
           "        if not isinstance(client_key, ClientPublicKey):\n            raise TypeError(\"attach takes",
           "        if False:\n            raise TypeError(\"attach takes"),
    # I11f, I11g: a keyless caller cannot evict a live nonce or grow the log
    Mutant("I11-challenge-evicts-live-nonce", "I11",
           '            if len(book) >= NONCE_RECORDS:\n                raise BridgeError("challenge budget exhausted (I11f)")',
           '            while len(book) >= NONCE_RECORDS:\n                book.pop(next(iter(book)))'),
    # I11a: a challenge refusal names the lifecycle state
    Mutant("I11-challenge-leaks-state", "I11",
           '            raise BridgeError(CHALLENGE_REFUSED, reason="refused")',
           '            raise BridgeError("session is TERMINATED (I6)" if s is not None\n'
           '                              and s.life == Lifecycle.TERMINATED\n'
           '                              else CHALLENGE_REFUSED,\n'
           '                              reason="terminated" if s is not None\n'
           '                              and s.life == Lifecycle.TERMINATED\n'
           '                              else "refused")'),
    # I11a: a re-attach refusal names the lifecycle state
    Mutant("I11-reattach-leaks-state", "I11",
           '            raise BridgeError(RESUME_REFUSED, reason="refused")',
           '            raise BridgeError("session is TERMINATED (I6)" if s is not None\n'
           '                              and s.life == Lifecycle.TERMINATED\n'
           '                              else RESUME_REFUSED,\n'
           '                              reason="terminated" if s is not None\n'
           '                              and s.life == Lifecycle.TERMINATED\n'
           '                              else "refused")'),
    Mutant("I11-unauthenticated-rejections-unbounded", "I11g",
           "            if logged >= UNAUTH_LOG_LIMIT:",
           "            if False:"),
    Mutant("I11-add-client-accepts-signing-key", "I11",
           "        if not isinstance(new_key, ClientPublicKey):",
           "        if False:"),
    # rule Q: a log that cannot be replayed freezes its own session only
    Mutant("Q-malformed-log-aborts-recovery", "Q",
           "            except Exception:\n                # A log that cannot be replayed",
           "            except ZeroDivisionError:\n                # A log that cannot be replayed"),
    # I11-REVOKE: unsigned revocation requests are bounded
    Mutant("I11-REVOKE-requests-unbounded", "I11-REVOKE",
           "            if asked >= REVOCATION_REQUEST_LIMIT:",
           "            if False:"),
    # I11-REVOKE: a bare terminate cannot end a key_exhausted session
    Mutant("I11-REVOKE-bare-terminate-ends-exhausted-session", "I11-REVOKE",
           "        if s.key_exhausted and not s.quarantined:\n            self._check_timers(sid)          # an expired session is over",
           "        if False:\n            self._check_timers(sid)          # an expired session is over"),
    Mutant("I11-REVOKE-exhausted-refusal-blocks-quarantine-exit", "I11-REVOKE",
           "        if s.key_exhausted and not s.quarantined:\n            self._check_timers(sid)          # an expired session is over",
           "        if s.key_exhausted:\n            self._check_timers(sid)          # an expired session is over"),
    Mutant("I11-REVOKE-exhausted-terminate-skips-timers", "I11-REVOKE",
           "            self._check_timers(sid)          # an expired session is over\n            if s.life == Lifecycle.TERMINATED:\n                return\n            raise BridgeError(\"session is KEY_EXHAUSTED: terminate needs \"",
           "            raise BridgeError(\"session is KEY_EXHAUSTED: terminate needs \""),
    # I11a, I15: a caller is not told which key ids a session registers
    Mutant("I11-unknown-key-distinguishable", "I11",
           "    return \"bad_signature\" if reason == \"unknown_key\" else reason",
           "    return reason"),
    # Appendix B: the handlers of attach, resolve, extend and the operator events
    Mutant("WIRESERVER-attach-asks-the-transport-hook", "WIRE",
           "    \"resolve\", \"delivered\", \"completed\", \"narrow\", \"extend\", \"terminate\"})",
           "    \"resolve\", \"delivered\", \"completed\", \"narrow\", \"extend\", \"terminate\",\n    \"attach\"})",
           "wire_server.py"),
    Mutant("WIRESERVER-resolve-not-authenticated", "WIRE",
           "    \"resolve\", \"delivered\", \"completed\", \"narrow\", \"extend\", \"terminate\"})",
           "    \"delivered\", \"completed\", \"narrow\", \"extend\", \"terminate\"})",
           "wire_server.py"),
    Mutant("WIRESERVER-extend-not-authenticated", "WIRE",
           "    \"resolve\", \"delivered\", \"completed\", \"narrow\", \"extend\", \"terminate\"})",
           "    \"resolve\", \"delivered\", \"completed\", \"narrow\", \"terminate\"})",
           "wire_server.py"),
    Mutant("WIRESERVER-attach-grant-dropped", "WIRE",
           "        self.bridge.attach(ident, key, m.get(\"grant\"), m.get(\"signature\"))",
           "        self.bridge.attach(ident, key, None, m.get(\"signature\"))",
           "wire_server.py"),
    Mutant("WIRESERVER-extend-revert-not-reported", "WIRE",
           "        status = \"revert_requested\" if out == \"REVERT\" else \"unchanged\"",
           "        status = \"unchanged\"", "wire_server.py"),
    Mutant("WIRESERVER-operator-signature-dropped", "WIRE",
           "            sid, m[\"key_id\"], m[\"public_key\"], signature=m.get(\"signature\"),",
           "            sid, m[\"key_id\"], m[\"public_key\"], signature=None,",
           "wire_server.py"),
    Mutant("WIRESERVER-not-exhausted-named-as-exhausted", "WIRE",
           '            raise BridgeError("session is not key_exhausted",\n                              reason="not_key_exhausted")\n        self._operator_verified(\n            lambda b, q, h: _terminate_bytes(b, sid, reason, q, h),',
           '            raise BridgeError("session is not key_exhausted",\n                              reason="key_exhausted")\n        self._operator_verified(\n            lambda b, q, h: _terminate_bytes(b, sid, reason, q, h),',
           "conformance_suite.py"),
    # Appendix B: unsigned ops pass the transport's authentication hook
    Mutant("WIRESERVER-authentication-hook-not-consulted", "WIRE",
           "        if (self.authenticate is not None and msg[\"op\"] in UNSIGNED_OPS\n                and not self.authenticate(msg[\"op\"], msg)):",
           "        if False:", "wire_server.py"),
    Mutant("WIRESERVER-authentication-hook-gets-no-message", "WIRE",
           "                and not self.authenticate(msg[\"op\"], msg)):",
           "                and not self.authenticate(msg[\"op\"], {})):", "wire_server.py"),
    Mutant("WIRESERVER-disconnect-not-authenticated", "WIRE",
           '    "disconnect", "escalate", "submit_tool_call", "answer_tool_call",\n',
           '    "escalate", "submit_tool_call", "answer_tool_call",\n', "wire_server.py"),
    Mutant("WIRESERVER-escalate-not-authenticated", "WIRE",
           '    "disconnect", "escalate", "submit_tool_call", "answer_tool_call",\n',
           '    "disconnect", "submit_tool_call", "answer_tool_call",\n', "wire_server.py"),
    Mutant("WIRESERVER-submit-tool-call-not-authenticated", "WIRE",
           '    "disconnect", "escalate", "submit_tool_call", "answer_tool_call",\n',
           '    "disconnect", "escalate", "answer_tool_call",\n', "wire_server.py"),
    Mutant("WIRESERVER-answer-tool-call-not-authenticated", "WIRE",
           '    "disconnect", "escalate", "submit_tool_call", "answer_tool_call",\n',
           '    "disconnect", "escalate", "submit_tool_call",\n', "wire_server.py"),
    Mutant("WIRESERVER-delivered-not-authenticated", "WIRE",
           '    "resolve", "delivered", "completed", "narrow", "extend", "terminate"})',
           '    "resolve", "completed", "narrow", "extend", "terminate"})', "wire_server.py"),
    Mutant("WIRESERVER-completed-not-authenticated", "WIRE",
           '    "resolve", "delivered", "completed", "narrow", "extend", "terminate"})',
           '    "resolve", "delivered", "narrow", "extend", "terminate"})', "wire_server.py"),
    Mutant("WIRESERVER-narrow-not-authenticated", "WIRE",
           '    "resolve", "delivered", "completed", "narrow", "extend", "terminate"})',
           '    "resolve", "delivered", "completed", "extend", "terminate"})', "wire_server.py"),
    Mutant("WIRESERVER-terminate-not-authenticated", "WIRE",
           '    "resolve", "delivered", "completed", "narrow", "extend", "terminate"})',
           '    "resolve", "delivered", "completed", "narrow", "extend"})', "wire_server.py"),
]

# --- Canonical JSON mutants (jcs.py) -----------------------------------------

CANON_MUTANTS = [
    Mutant("CANON-non-ascii-escaped", "CANON",
           "        elif c < 0x20:", "        elif c < 0x20 or c > 0x7e:",
           file="jcs.py"),
    Mutant("CANON-float-printed-as-python", "CANON",
           "        return _number(v)", "        return repr(v)", file="jcs.py"),
    Mutant("CANON-keys-by-code-point", "CANON",
           'keys = sorted(v, key=lambda k: k.encode("utf-16-be", "surrogatepass"))',
           "keys = sorted(v)", file="jcs.py"),
    Mutant("CANON-large-integer-accepted", "CANON",
           "        if abs(v) > MAX_SAFE_INT:", "        if False:",
           file="jcs.py"),
    Mutant("CANON-exponent-threshold", "CANON",
           "    elif -6 < n <= 0:", "    elif -9 < n <= 0:", file="jcs.py"),
]

# --- Wire-format mutants --------------------------------

WIRE_SOURCE = HERE / "wire.py"

WIRE_MUTANTS = [
    Mutant("WIRE-canonical-wrong-order", "WIRE",
           '    return canonicalize(obj)',
           '    return json.dumps(obj, sort_keys=False, separators=(",", ":")).encode()'),
    Mutant("WIRE-canonical-extra-whitespace", "WIRE",
           '    return canonicalize(obj)',
           '    return json.dumps(obj, sort_keys=True, separators=(", ", ": ")).encode()'),
    Mutant("WIRE-canonical-ascii-escaped", "WIRE",
           '    return canonicalize(obj)',
           '    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()'),
    Mutant("WIRE-signature-wrong-scope", "WIRE",
           '    return canonical_bytes(values)',
           '    return canonical_bytes(values[:1] + values[2:])'),
    Mutant("WIRE-resume-tag-dropped", "WIRE",
           '    return canonical_for_signature([tag, session_id, key_id, nonce, seq, hash])',
           '    return canonical_for_signature([session_id, key_id, nonce, seq, hash])'),
    Mutant("WIRE-resume-key-id-dropped", "WIRE",
           '    return canonical_for_signature([tag, session_id, key_id, nonce, seq, hash])',
           '    return canonical_for_signature([tag, session_id, nonce, seq, hash])'),
]


WIRESERVER_MUTANTS = [
    Mutant("WIRESERVER-noncanonical-accepted", "WIRE",
           "            if wire.canonical_bytes(msg) != data:",
           "            if False:", "wire_server.py"),
    Mutant("WIRESERVER-add-client-nonce-dropped", "WIRE",
           """        self.bridge.add_client_key(sid, m["via_key_id"], new, m["nonce"],""",
           """        self.bridge.add_client_key(sid, m["via_key_id"], new, "",""",
           "wire_server.py"),
    Mutant("WIRESERVER-reattach-not-completed", "WIRE",
           "        events = self.bridge.client_reattach(sid, self._request(m))",
           "        events = self.bridge.begin_resume(sid, self._request(m))",
           "wire_server.py"),
    Mutant("WIRESERVER-reason-lost", "WIRE",
           """    return exc.reason
""",
           """    return "refused"
""", "wire_server.py"),
]


def run_wireserver_mutant(mutant: Mutant) -> tuple[Mutant, str]:
    """Run a wire_server.py mutant through ``run_vectors.py --wire``."""
    src = (HERE / mutant.file).read_text()
    if src.count(mutant.old) != 1:
        return mutant, f"PATCH-ERROR (anchor found {src.count(mutant.old)}x)"
    with tempfile.TemporaryDirectory(prefix="mut-wsrv-") as d:
        for name in (*SUPPORT, "run_vectors.py"):
            (Path(d) / name).write_text((HERE / name).read_text())
        (Path(d) / "vectors").symlink_to(HERE / "vectors")
        (Path(d) / mutant.file).write_text(src.replace(mutant.old, mutant.new))
        proc = subprocess.run(
            [sys.executable, "-I", str(Path(d) / "run_vectors.py"), "--wire"],
            cwd=d, capture_output=True, text=True, timeout=600)
    if proc.returncode == 0:
        return mutant, "SURVIVED"
    if proc.returncode == 1 and re.search(r"^FAIL ", proc.stdout, re.M):
        FAILED_BY[mutant.name] = sorted(set(re.findall(r"^FAIL (V\d+)", proc.stdout, re.M)))
        return mutant, "killed"
    tail = (proc.stderr or proc.stdout).strip().splitlines()[-1:]
    return mutant, (f"ERROR (run_vectors exit {proc.returncode}, no failed vector; "
                    f"not a vector failure: {tail})")


def run_wire_mutant(mutant: Mutant) -> tuple[Mutant, str]:
    """Run a wire.py mutant and check that the canonical encoding
    smoke test catches it."""
    src = WIRE_SOURCE.read_text()
    if src.count(mutant.old) != 1:
        return mutant, f"PATCH-ERROR (anchor found {src.count(mutant.old)}x)"
    with tempfile.TemporaryDirectory(prefix="mut-wire-") as d:
        path = Path(d) / "wire.py"
        path.write_text(src.replace(mutant.old, mutant.new))
        (Path(d) / "jcs.py").write_text((HERE / "jcs.py").read_text())
        test = """
import sys
sys.path.insert(0, %r)
import wire

# Test 1: canonical_bytes is deterministic
b1 = wire.canonical_bytes({'b': 1, 'a': 2})
b2 = wire.canonical_bytes({'a': 2, 'b': 1})
assert b1 == b2, f"canonical_bytes not deterministic: {b1!r} != {b2!r}"

# Test 2: canonical_for_signature produces expected bytes
sig = wire.canonical_for_signature(['sess-001', 'n1', 6, 'h1'])
assert sig == b'["sess-001","n1",6,"h1"]', f"wrong sig scope: {sig!r}"

# Test 2b: the re-attach and join proofs sign different, pinned bytes
r = wire.resume_signature_input('reattach', 's', 'k', 'n', 1, 'h')
assert r == b'["bc/v1/reattach","s","k","n",1,"h"]', r
j = wire.resume_signature_input('join', 's', 'k', 'n', 1, 'h')
assert j == b'["bc/v1/join","s","k","n",1,"h"]', j

# Test 2c: RFC 8785 bytes: raw UTF-8, no ASCII escaping, 1.0 is 1
assert wire.canonical_bytes('\u00e9') == '"\u00e9"'.encode(), "non-ASCII"
assert wire.canonical_bytes({'t': 1.0}) == b'{"t":1}', "float"

# Test 3: challenge roundtrip
msg = wire.op_challenge(session_id='sess-001')
decoded = wire.decode_message(msg)
assert decoded == {'op': 'challenge', 'session_id': 'sess-001'}, decoded

print("wire OK")
""" % str(path.parent)
        proc = subprocess.run(
            [sys.executable, "-I", "-c", test],
            cwd=d, capture_output=True, text=True, timeout=60)
    if proc.returncode == 0:
        return mutant, "SURVIVED"
    if proc.returncode == 1 and "AssertionError" in proc.stderr:
        return mutant, "killed"
    return mutant, f"ERROR (exit {proc.returncode}, no assertion failure; not a kill)"


FAILED_BY: dict[str, list[str]] = {}


def run_one(mutant: Mutant) -> tuple[Mutant, str]:
    src = (HERE / mutant.file).read_text()
    if src.count(mutant.old) != 1:
        return mutant, f"PATCH-ERROR (anchor found {src.count(mutant.old)}x)"
    with tempfile.TemporaryDirectory(prefix="mut-") as d:
        # the suite reads vectors/ and imports jcs.py from its own directory
        for name in SUPPORT:
            (Path(d) / name).write_text((HERE / name).read_text())
        (Path(d) / "vectors").symlink_to(HERE / "vectors")
        (Path(d) / mutant.file).write_text(src.replace(mutant.old, mutant.new))
        path = Path(d) / "conformance_suite.py"
        proc = subprocess.run(
            [sys.executable, "-I", "-m", "pytest", "-q", "-rf",
             "-p", "no:cacheprovider", str(path)],
            cwd=d, capture_output=True, text=True, timeout=600)
    verdict, failed = classify(proc)
    FAILED_BY[mutant.name] = failed
    return mutant, verdict


def main() -> int:
    jobs = 4
    if "-j" in sys.argv:
        jobs = int(sys.argv[sys.argv.index("-j") + 1])

    base = subprocess.run(
        [sys.executable, "-I", "-m", "pytest", "-q", "-p", "no:cacheprovider",
         str(SOURCE)], cwd=HERE, capture_output=True, text=True)
    if base.returncode != 0:
        print("baseline suite fails; fix it before mutating:\n"
              + base.stdout[-2000:])
        return 2

    # Controls: a patch that changes nothing must survive in every harness.
    # If it is "killed", the scratch copy fails by itself (a missing module,
    # say) and every verdict below would be vacuous.
    controls = [
        (run_one, Mutant(name="control-no-change", invariant="-",
                         old="import os\n", new="import os\n")),
        (run_wireserver_mutant, Mutant(
            name="control-no-change", invariant="-", old="import wire\n",
            new="import wire\n", file="wire_server.py"))]
    for runner, control in controls:
        outcome = runner(control)[1]
        if outcome != "SURVIVED":
            print(f"control {runner.__name__}: a patch that changes nothing "
                  f"was {outcome}; the mutation harness is not sound")
            return 2

    covered = {m.invariant for m in MUTANTS}
    missing = [i for i in INVARIANTS if i not in covered]

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        results = list(pool.map(run_one, MUTANTS + CANON_MUTANTS))
        wire_results = list(pool.map(run_wire_mutant, WIRE_MUTANTS))
        wire_results += list(pool.map(run_wireserver_mutant,
                                      WIRESERVER_MUTANTS))

    bad = 0
    tags = test_tags()
    unattributed = []
    # every traceability row a mutant can name, not only I1..I15 and TIMERS
    checked_rows = set(INVARIANTS) | set(sys.modules["traceability"].ROW_IDS)
    for mutant, outcome in results:
        failed = FAILED_BY.get(mutant.name, [])
        shown = ""
        if outcome == "killed":
            hit = [t for t in failed if mutant.invariant in tags.get(t, set())]
            shown = f"  <- {','.join(failed[:6])}{'...' if len(failed) > 6 else ''}"
            if not hit and mutant.invariant in checked_rows:
                unattributed.append(mutant)
                shown += "  [no failing test carries the tag]"
        print(f"{outcome:9s} {mutant.invariant:4s} {mutant.name}{shown}")
        bad += outcome != "killed"
    for mutant, outcome in wire_results:
        print(f"{outcome:9s} {mutant.invariant:4s} {mutant.name}")
        bad += outcome != "killed"
    killed = sum(o == "killed" for _, o in results + wire_results)
    total = len(results) + len(wire_results)
    covered = {m.invariant for m in MUTANTS + CANON_MUTANTS + WIRE_MUTANTS
                  + WIRESERVER_MUTANTS}
    print(f"\n{killed}/{total} mutants killed; "
          f"{len(covered)} invariants covered")
    if missing:
        print("invariants without a mutant:", ", ".join(missing))
    attributed = {m.invariant for m, o in results
                  if o == "killed" and m not in unattributed}
    lacking = [i for i in INVARIANTS if i not in attributed]
    print(f"{len(unattributed)} kills by no test tagged with the mutant's invariant; "
          f"invariants with no attributed kill: {', '.join(lacking) or 'none'}")
    strict = "--strict-attribution" in sys.argv and bool(lacking or unattributed)
    return 1 if (bad or missing or strict) else 0


if __name__ == "__main__":
    sys.exit(main())
