#!/usr/bin/env python3
"""
Mutation check for the Rust crate (rust-bridge/).

A small, hand-chosen set of one-site textual mutants of the rules the
paper rests on: request-signature verification (I11c), nonce spend, expiry
and replay (I9, I11b, I11d, I8), revoked-key rejection (I11-REVOKE), the
registered-key check (I15), the acknowledged-prefix check (I4) and the
hash chain (I5), and the rules of the wire front-end (the canonical
envelope, reason names, the authentication hook, op dispatch).  Each mutant is written to a scratch copy of the crate
(with the vectors it reads) and `cargo test` is run against it.  A mutant
is *killed* only if the build succeeds, cargo test exits with code 101 and
the output reports a failed test ("test result: FAILED" and a "---- ... ----"
failure block); a compile error or any other failure is reported as an error,
never as a kill, and the failing test names are printed.  A control that
patches a site and writes the same text back must pass before any mutant is
judged.  The script exits non-zero if a patch does not apply exactly once, a
mutant does not compile, the unmutated crate or the control fails, or any
mutant survives.

This is a sample for the highest-value rules, not one mutant per
invariant; the Python check (mutation_check.py) covers I1--I15.

Run (needs a Rust toolchain; first run downloads the crate dependencies):
    python3 -I mutation_check_rust.py [--only NAME]
Build output goes to a scratch directory, never to the crate's own target
directory (cargo would mistake a mutated build of the copy for a build of
the crate); set MUTATION_TARGET_DIR to a directory used only by this script
to keep dependency builds between runs.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
CRATE = HERE / "rust-bridge"
VECTORS = HERE / "vectors"


# tests that run every vector on the file fixture: a mutant that only they
# fail is not shown to be caught by a rule test
STORAGE_ONLY = {"all_vectors_pass_on_file_storage"}


@dataclass(frozen=True)
class Mutant:
    name: str
    rule: str
    file: str
    old: str
    new: str


MUTANTS = [
    # signature verification
    Mutant("SIG-skip-check", "I11c", "src/bridge.rs",
           """        if !ok {
            return Ok(Some("bad_signature")); // I11c""",
           """        if !ok && false {
            return Ok(Some("bad_signature")); // I11c"""),
    Mutant("SIG-ed25519-accepts-any", "I11c", "src/types.rs",
           """        let Ok(sig) = Signature::from_slice(&raw) else { return false };
        vk.verify(message, &sig).is_ok()""",
           """        let Ok(sig) = Signature::from_slice(&raw) else { return false };
        let _ = vk.verify(message, &sig);
        true"""),
    Mutant("SIG-p256-accepts-any", "I11c", "src/types.rs",
           """        let sig = sig.normalize_s().unwrap_or(sig);
        vk.verify(message, &sig).is_ok()""",
           """        let sig = sig.normalize_s().unwrap_or(sig);
        let _ = vk.verify(message, &sig);
        true"""),
    Mutant("KEY-unregistered-accepted", "I15", "src/bridge.rs",
           "        if !s.keys.contains(&req.key_id) {\n            return Ok(Some(\"unknown_key\"));",
           "        if false {\n            return Ok(Some(\"unknown_key\"));"),
    # add_client authorisation (I15d)
    Mutant("ADDCLIENT-skip-verify", "I15", "src/bridge.rs",
           """        if !ok {
            return refuse("bad_signature");""",
           """        if !ok && false {
            return refuse("bad_signature");"""),
    Mutant("ADDCLIENT-nonce-not-spent", "I15", "src/bridge.rs",
           "        rec.used = true; // spent by the first authentic presentation, as in I11d",
           "        // nonce left unspent"),
    Mutant('ADDCLIENT-revoked-key-authorises', 'I15', 'src/bridge.rs',
           '        if s.revoked.contains(via_key_id) {',
           '        if false && s.revoked.contains(via_key_id) {'),
    Mutant("ADDCLIENT-domain-tag-dropped", "I15", "src/types.rs",
           "canonical_bytes(&json!([ADD_CLIENT_DOMAIN, sid, via_key_id, new_key_id, scheme, public_key_hex, nonce]))",
           "canonical_bytes(&json!([sid, via_key_id, new_key_id, scheme, public_key_hex, nonce]))"),
    # the approval hash leaves out the tool and the permission
    Mutant("CALL-hash-omits-tool-and-permission", "I14", "src/types.rs",
           """    content_hash(&json!({"tool": tool, "permission": permission, "content": content}))""",
           """    content_hash(content)"""),
    # the forward drops the content hashed at queue time
    Mutant("CALL-forwards-without-hashed-content", "I14", "src/bridge.rs",
           """                    content: ev.payload["content"].clone(),
                };
                self.send(sid, &key, call);""",
           """                    content: Value::Null,
                };
                self.send(sid, &key, call);"""),
    # a challenge refusal names the lifecycle state
    Mutant("CHALLENGE-leaks-state", "I11", "src/bridge.rs",
           "            _ => return Err(BridgeError::with_reason(CHALLENGE_REFUSED, \"refused\")),",
           "            Some(s) if s.quarantined => return Err(BridgeError::with_reason(\"session is QUARANTINED\", \"quarantined\")),\n"
           "            _ => return Err(BridgeError::with_reason(CHALLENGE_REFUSED, \"refused\")),"),
    # a re-attach refusal names the lifecycle state
    Mutant("RESUME-leaks-state", "I11", "src/bridge.rs",
           "            _ => Err(BridgeError::with_reason(RESUME_REFUSED, \"refused\")),",
           "            Some(s) if s.quarantined => Err(BridgeError::with_reason(\"session is QUARANTINED\", \"quarantined\")),\n"
           "            _ => Err(BridgeError::with_reason(RESUME_REFUSED, \"refused\")),"),
    # nonce spend, expiry, replay
    Mutant("NONCE-not-spent", "I11d", "src/bridge.rs",
           "        rec.used = true; // I11d: spent by the first authentic presentation",
           "        // nonce left unspent"),
    Mutant("NONCE-expiry-ignored", "I9", "src/bridge.rs",
           "        if now - rec.issued >= t_nonce {\n            return Ok(Some(\"nonce_expired\"));",
           "        if false && now - rec.issued >= t_nonce {\n            return Ok(Some(\"nonce_expired\"));"),
    Mutant('NONCE-unknown-accepted', 'I11b', 'src/bridge.rs',
           '            return Ok(Some("nonce_unknown")); // I11b',
           '            return Ok(None);'),
    Mutant('REPLAY-transport-replay-accepted', 'I8', 'src/bridge.rs',
           '        if transport_replay {\n            reason = Some("transport_replay"); // I8',
           '        if false {\n            reason = Some("transport_replay"); // I8'),
    # revoked-key rejection
    Mutant("REVOKE-revoked-key-accepted", "I11-REVOKE", "src/bridge.rs",
           "        if s.revoked.contains(&req.key_id) {",
           "        if false && s.revoked.contains(&req.key_id) {"),
    Mutant("REVOKE-nonce-not-spent", "I11d", "src/bridge.rs",
           """                rec.used = true;
            }
            return Ok(Some("revoked_key"));""",
           """            }
            return Ok(Some("revoked_key"));"""),
    Mutant('REVOKE-hard-res-not-abandoned', 'I11-REVOKE', 'src/bridge.rs',
           'if (reason == "compromise" && last_connected) || verifying {',
           'if reason == "compromise" && last_connected {'),
    # acknowledged prefix
    Mutant("PREFIX-hash-unchecked", "I4", "src/bridge.rs",
           ".is_some_and(|e| e.hash() == req.hash);",
           ".is_some();"),
    # hash chain
    Mutant("CHAIN-writer-drops-prev-hash", "I5", "src/bridge.rs",
           "                prev_hash: prev,\n                payload,",
           "                prev_hash: String::new(),\n                payload,"),
    Mutant("CHAIN-verifier-ignores-prev-hash", "I5", "src/bridge.rs",
           "            if ev.sequence != i as u64 || ev.prev_hash != prev {",
           "            if ev.sequence != i as u64 {"),
    Mutant("CHAIN-verifier-ignores-sequence", "I5", "src/bridge.rs",
           "            if ev.sequence != i as u64 || ev.prev_hash != prev {",
           "            if ev.prev_hash != prev {"),
    # a keyless caller cannot evict a live nonce or grow the log
    Mutant("NONCE-challenge-evicts-live-nonce", "I11f", "src/bridge.rs",
           """            book.retain(|r| !r.used && issued - r.issued < t_nonce);
            if book.len() >= NONCE_RECORDS {
                return Err(BridgeError::new("challenge budget exhausted (I11f)"));
            }""",
           """            while book.len() >= NONCE_RECORDS {
                book.pop_front();
            }"""),
    Mutant("LOG-unauthenticated-rejections-unbounded", "I11g", "src/bridge.rs",
           "            if *logged >= UNAUTH_LOG_LIMIT {",
           "            if false && *logged >= UNAUTH_LOG_LIMIT {"),
    # the re-attach/join proof binds the operation tag and the key id
    Mutant("RESUME-domain-tag-dropped", "I11c", "src/types.rs",
           "canonical_bytes(&json!([op.tag(), sid, key_id, nonce, seq, hash]))",
           "canonical_bytes(&json!([sid, key_id, nonce, seq, hash]))"),
    Mutant("RESUME-key-id-dropped", "I11c", "src/types.rs",
           "canonical_bytes(&json!([op.tag(), sid, key_id, nonce, seq, hash]))",
           "canonical_bytes(&json!([op.tag(), sid, nonce, seq, hash]))"),
    Mutant("RESUME-join-verified-as-reattach", "I11c", "src/bridge.rs",
           "self.begin_resume_as(ResumeOp::Join, sid, req, transport_replay)",
           "self.begin_resume_as(ResumeOp::Reattach, sid, req, transport_replay)"),
    Mutant("RESUME-join-tagged-as-reattach", "I11c", "src/types.rs",
           'ResumeOp::Join => "bc/v1/join",', 'ResumeOp::Join => "bc/v1/reattach",'),
    # the key registry is scoped to a session and rebuilt from the log
    Mutant("REGISTRY-global-by-key-id", "I11", "src/types.rs",
           "        (sid.to_string(), key_id.to_string())\n    }\n}",
           "        (String::new(), key_id.to_string())\n    }\n}"),
    Mutant("REGISTRY-reregistration-allowed", "I11", "src/types.rs",
           "        if keys.contains_key(&slot) {\n            return Err(",
           "        if false && keys.contains_key(&slot) {\n            return Err("),
    Mutant("RECOVERY-malformed-log-not-isolated", "I11", "src/bridge.rs",
           "            if !replayable(&log) {",
           "            if false && !replayable(&log) {"),
    Mutant("REVOKE-requests-unbounded", "I11", "src/bridge.rs",
           "            if asked >= REVOCATION_REQUEST_LIMIT {",
           "            if false && asked >= REVOCATION_REQUEST_LIMIT {"),
    Mutant("REGISTRY-recovery-leaves-differing-entries", "I11", "src/bridge.rs",
           "                Some(r) => r.scheme == *scheme && hex::encode(&r.material) == *public_hex,",
           "                Some(_) => true,"),
    Mutant("REGISTRY-recovery-leaves-extra-entries", "I11", "src/bridge.rs",
           "            if !s.keys.contains(&k) {\n                self.storage.unregister_key(sid, &k)?;",
           "            if false && !s.keys.contains(&k) {\n                self.storage.unregister_key(sid, &k)?;"),
    Mutant("REGISTRY-recovery-leaves-missing-entries", "I11", "src/bridge.rs",
           "                None => false,\n            };\n            if !same {\n                let material",
           "                None => true,\n            };\n            if !same {\n                let material"),
    Mutant("REGISTRY-recovery-repair-unreported", "I11", "src/bridge.rs",
           '"registry_repaired": repaired})',
           '"registry_repaired": Vec::<String>::new()})'),
    Mutant("REGISTRY-client-added-logs-wrong-key", "I11", "src/bridge.rs",
           '"public_key": hex::encode(material)}),',
           '"public_key": hex::encode(new_key_id)}),'),
    Mutant("REGISTRY-failed-attach-keeps-entry", "I11", "src/bridge.rs",
           "            )],\n        );\n        if let Err(e) = committed {\n            self.storage.unregister_key(sid, &key.key_id)?;\n            return Err(e);\n        }\n        Ok(())\n    }\n\n    /// CLIENT_ADDED",
           "            )],\n        );\n        if let Err(e) = committed {\n            return Err(e);\n        }\n        Ok(())\n    }\n\n    /// CLIENT_ADDED"),
    # operator signatures bind the bridge and the log position
    Mutant("OPERATOR-revoke-omits-bridge-id", "I-OPERATOR", "src/types.rs",
           "json!([REVOKE_DOMAIN, bridge_id, sid, key_id, reason, seq, head])",
           "json!([REVOKE_DOMAIN, sid, key_id, reason, seq, head])"),
    Mutant("OPERATOR-add-key-omits-bridge-id", "I-OPERATOR", "src/types.rs",
           "json!([ADD_KEY_DOMAIN, bridge_id, sid, key_id, scheme, public_key_hex, seq, head])",
           "json!([ADD_KEY_DOMAIN, sid, key_id, scheme, public_key_hex, seq, head])"),
    Mutant("OPERATOR-terminate-omits-bridge-id", "I-OPERATOR", "src/types.rs",
           "json!([TERMINATE_DOMAIN, bridge_id, sid, reason, seq, head])",
           "json!([TERMINATE_DOMAIN, sid, reason, seq, head])"),
    Mutant("OPERATOR-revoke-omits-position", "I-OPERATOR", "src/types.rs",
           "json!([REVOKE_DOMAIN, bridge_id, sid, key_id, reason, seq, head])",
           "json!([REVOKE_DOMAIN, bridge_id, sid, key_id, reason])"),
    Mutant("OPERATOR-add-key-omits-position", "I-OPERATOR", "src/types.rs",
           "json!([ADD_KEY_DOMAIN, bridge_id, sid, key_id, scheme, public_key_hex, seq, head])",
           "json!([ADD_KEY_DOMAIN, bridge_id, sid, key_id, scheme, public_key_hex])"),
    Mutant("OPERATOR-terminate-omits-position", "I-OPERATOR", "src/types.rs",
           "json!([TERMINATE_DOMAIN, bridge_id, sid, reason, seq, head])",
           "json!([TERMINATE_DOMAIN, bridge_id, sid, reason])"),
    Mutant("OPERATOR-revoke-binds-sequence-only", "I-OPERATOR", "src/types.rs",
           "json!([REVOKE_DOMAIN, bridge_id, sid, key_id, reason, seq, head])",
           "json!([REVOKE_DOMAIN, bridge_id, sid, key_id, reason, seq])"),
    # a re-attach on an attached session is refused; join is the way in
    Mutant("RESUME-reattach-on-attached-session-joins", "I11", "src/bridge.rs",
           "        if reason.is_none() && s.cell.att == Attachment::Att && op == ResumeOp::Reattach {",
           "        if false {"),
    Mutant('RESUME-already-attached-before-authentication', 'I11', 'src/bridge.rs',
           '        let mut reason = self.reject_reason(op, sid, &s, req)?;\n',
           '        let mut reason = self.reject_reason(op, sid, &s, req)?;\n        if s.cell.att == Attachment::Att && op == ResumeOp::Reattach {\n            reason = Some("already_attached");\n        }\n'),
    Mutant("RESUME-join-refused-as-already-attached", "I11", "src/bridge.rs",
           "        if reason.is_none() && s.cell.att == Attachment::Att && op == ResumeOp::Reattach {",
           "        if reason.is_none() && s.cell.att == Attachment::Att {"),
    # attach: the grant binds the public key and the bridge; possession is proved
    Mutant("ATTACH-possession-not-checked", "I-GRANT", "src/bridge.rs",
           "        if !possessed {", "        if !possessed && false {"),
    Mutant("GRANT-omits-public-key", "I-GRANT", "src/types.rs",
           "        json!(key.scheme),\n        json!(hex::encode(&key.material)),\n", ""),
    Mutant("GRANT-omits-bridge-id", "I-GRANT", "src/types.rs",
           "    let mut v = vec![json!(GRANT_DOMAIN)];\n    v.extend(attach_fields(bridge_id, identity, key));",
           "    let mut v = vec![json!(GRANT_DOMAIN)];\n    v.extend(attach_fields(bridge_id, identity, key).into_iter().skip(1));"),
    Mutant("ATTACH-proof-omits-bridge-id", "I-GRANT", "src/types.rs",
           "    let mut v = vec![json!(ATTACH_DOMAIN)];\n    v.extend(attach_fields(bridge_id, identity, key));",
           "    let mut v = vec![json!(ATTACH_DOMAIN)];\n    v.extend(attach_fields(bridge_id, identity, key).into_iter().skip(1));"),
    Mutant("ATTACH-proof-uses-grant-domain", "I-GRANT", "src/types.rs",
           'pub const ATTACH_DOMAIN: &str = "bc/v1/attach";',
           'pub const ATTACH_DOMAIN: &str = "bc/v1/grant";'),
    # RFC 8785 canonical JSON
    Mutant("CANON-non-ascii-escaped", "I5", "src/wire.rs",
           "            c => out.push(c),",
           '            c if (c as u32) > 0x7e => out.push_str(&format!("\\\\u{:04x}", c as u32)),\n            c => out.push(c),'),
    Mutant("CANON-keys-by-code-point", "I5", "src/wire.rs",
           "members.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));",
           "members.sort_by(|a, b| a.0.cmp(b.0));"),
    Mutant("CANON-float-printed-natively", "I5", "src/wire.rs",
           "out.push_str(&es6_number(n.as_f64().ok_or(\"number has no f64 form\")?)?);",
           "out.push_str(&n.to_string());"),
    Mutant("CANON-large-integer-accepted", "I5", "src/wire.rs",
           "                if u > MAX_SAFE_INT {",
           "                if false && u > MAX_SAFE_INT {"),
    # key_exhausted keeps its timers (L1, L2)
    Mutant("EXHAUST-timers-frozen", "L1", "src/bridge.rs",
           "        let s = self.sessions[sid].clone();\n        if s.cell.life == Life::Terminated || s.quarantined {\n            return Ok(());\n        }\n        let now = self.now();",
           "        let s = self.sessions[sid].clone();\n        if s.cell.life == Life::Terminated || s.quarantined || s.key_exhausted {\n            return Ok(());\n        }\n        let now = self.now();"),
    Mutant("EXHAUST-restart-skipped", "I12", "src/bridge.rs",
           "            if b.sessions[&sid].cell.life == Life::Terminated || b.sessions[&sid].quarantined {",
           "            if b.sessions[&sid].cell.life == Life::Terminated || b.sessions[&sid].quarantined || b.sessions[&sid].key_exhausted {"),
    Mutant("EXHAUST-refused-before-timers", "L1", "src/bridge.rs",
           "        if self.sessions[sid].key_exhausted && !exhausted_ok {\n            self.check_timers(sid)?;\n            if terminated(self) {\n                return Err(BridgeError::with_reason(\"session is TERMINATED (I6)\", \"terminated\"));\n            }\n",
           "        if self.sessions[sid].key_exhausted && !exhausted_ok {\n"),
    Mutant("EXHAUST-disconnect-refused", "L1", "src/bridge.rs",
           "        let s = self.enter_with(sid, true)?;",
           "        let s = self.enter_with(sid, false)?;"),
    Mutant('EXHAUST-add-key-after-expiry', 'L1', 'src/bridge.rs',
           '        if self.sessions.contains_key(sid) {\n            self.check_timers(sid)?;\n        }\n        let (seq, head) = self.head_of(sid);',
           '        let (seq, head) = self.head_of(sid);'),
    # wire front-end (wire_server.rs, Appendix B)
    Mutant("WIRE-non-canonical-accepted", "WIRE", "src/wire_server.rs",
           "            Ok(c) if c == data => {}",
           "            Ok(_) => {}"),
    Mutant("WIRE-unsigned-ops-skip-auth", "WIRE", "src/wire_server.rs",
           "        if unsigned {\n            if let Some(auth)",
           "        if false && unsigned {\n            if let Some(auth)"),
    Mutant("WIRE-auth-asked-of-signed-ops", "WIRE", "src/wire_server.rs",
           "        if unsigned {\n            if let Some(auth)",
           "        if true {\n            if let Some(auth)"),
    Mutant("WIRE-missing-field-defaults", "WIRE", "src/wire_server.rs",
           "std::result::Result<&'a str, Malformed> {\n    m.get(k).and_then(Value::as_str).ok_or(Malformed)",
           "std::result::Result<&'a str, Malformed> {\n    Ok(m.get(k).and_then(Value::as_str).unwrap_or(\"\"))"),
    Mutant("WIRE-resume-reason-hidden", "WIRE", "src/wire_server.rs",
           "    err.1.to_string()",
           "    \"refused\".to_string()"),
    Mutant("WIRE-unknown-session-not-named", "WIRE", "src/wire_server.rs",
           "    err.1.to_string()",
           "    if err.1 == \"unknown_session\" { \"refused\".to_string() } else { err.1.to_string() }"),
    Mutant("WIRE-reattach-not-completed", "WIRE", "src/wire_server.rs",
           "                let events = if b.cell_of(sid).att == Attachment::Res {",
           "                let events = if false {"),
    Mutant("WIRE-join-is-reattach", "WIRE", "src/wire_server.rs",
           "                let events = b.join(sid, &req, false)?;",
           "                let events = b.begin_resume(sid, &req, false)?;"),
    Mutant("WIRE-answer-decision-inverted", "WIRE", "src/wire_server.rs",
           'text(m, "decision")? == "approve")?;',
           'text(m, "decision")? != "approve")?;'),
    Mutant("WIRE-duplicate-call-accepted", "WIRE", "src/wire_server.rs",
           'ToolOutcome::Duplicate => wire::encode_error(sid, "duplicate_key"),',
           'ToolOutcome::Duplicate => ack("queued", sid),'),
    Mutant("WIRE-queue-full-accepted", "WIRE", "src/wire_server.rs",
           'ToolOutcome::Rejected => wire::encode_error(sid, "queue_full"),',
           'ToolOutcome::Rejected => ack("queued", sid),'),
    Mutant("WIRE-resolve-not-authenticated", "WIRE", "src/wire_server.rs",
           """pub const UNSIGNED_OPS: [&str; 10] = [
    "disconnect", "escalate", "resolve", "submit_tool_call", "answer_tool_call",""",
           """pub const UNSIGNED_OPS: [&str; 9] = [
    "disconnect", "escalate", "submit_tool_call", "answer_tool_call","""),
    Mutant("WIRE-attach-grant-dropped", "WIRE", "src/wire_server.rs",
           """                    m.get("grant").and_then(Value::as_str),
                    m.get("signature").and_then(Value::as_str),
                )?;""",
           """                    None,
                    m.get("signature").and_then(Value::as_str),
                )?;"""),
    Mutant("WIRE-extend-revert-not-reported", "WIRE", "src/wire_server.rs",
           'AuthorityOutcome::Revert => "revert_requested",',
           'AuthorityOutcome::Revert => "unchanged",'),
    Mutant("WIRE-operator-signature-dropped", "WIRE", "src/wire_server.rs",
           'b.operator_add_key(sid, &key, m.get("signature").and_then(Value::as_str).unwrap_or(""))?;',
           'b.operator_add_key(sid, &key, "")?;'),
    Mutant("WIRE-not-exhausted-named-as-exhausted", "WIRE", "src/wire_server.rs",
           "    err.1.to_string()",
           "    if err.1 == \"not_key_exhausted\" { \"key_exhausted\".to_string() } else { err.1.to_string() }"),
    Mutant("EXHAUST-bare-terminate-ends-session", "I11-REVOKE", "src/bridge.rs",
           "        if s.key_exhausted && !s.quarantined {\n            self.check_timers(sid)?; // an expired session is over",
           "        if false {\n            self.check_timers(sid)?; // an expired session is over"),
    Mutant("EXHAUST-bare-terminate-blocks-quarantine-exit", "I11-REVOKE", "src/bridge.rs",
           "        if s.key_exhausted && !s.quarantined {\n            self.check_timers(sid)?; // an expired session is over",
           "        if s.key_exhausted {\n            self.check_timers(sid)?; // an expired session is over"),
    Mutant("EXHAUST-bare-terminate-skips-timers", "I11-REVOKE", "src/bridge.rs",
           "            self.check_timers(sid)?; // an expired session is over\n            if self.sessions[sid].cell.life == Life::Terminated {",
           "            if self.sessions[sid].cell.life == Life::Terminated {"),
    Mutant('RESUME-unknown-key-distinguishable', 'I11', 'src/bridge.rs',
           '    if reason == "unknown_key" || reason == "nonce_binding" {',
           '    if false {'),
    Mutant("WIRE-disconnect-ignores-key", "WIRE", "src/wire_server.rs",
           'b.client_disconnect(sid, m.get("key_id").and_then(Value::as_str), text(m, "reason")?)?;',
           'b.client_disconnect(sid, None, text(m, "reason")?)?;'),
    # the authentication hook is given the message that names the session
    Mutant("WIRE-authentication-hook-gets-no-message", "WIRE", "src/wire_server.rs",
           "                if !auth(&op, &msg) {",
           "                if !auth(&op, &Value::Null) {"),
    # state a bridge keeps per session is not shared between sessions
    Mutant('SESSION-nonce-looked-up-in-any-session', 'I11', 'src/bridge.rs',
           '        let rec = self.nonces.get_mut(sid).and_then(|b| b.iter_mut().find(|r| r.nonce == req.nonce));',
           '        let rec = self.nonces.values_mut().find_map(|b| b.iter_mut().find(|r| r.nonce == req.nonce));'),
    Mutant('SESSION-add-client-nonce-looked-up-in-any-session', 'I15', 'src/bridge.rs',
           '        let rec = self.nonces.get_mut(sid).and_then(|b| b.iter_mut().find(|r| r.nonce == nonce));',
           '        let rec = self.nonces.values_mut().find_map(|b| b.iter_mut().find(|r| r.nonce == nonce));'),
    Mutant('I11-add-client-names-the-lifecycle-before-the-signature', 'I11', 'src/bridge.rs',
           '        let known = self.sessions.get(sid).is_some_and(|s| s.keys.contains(via_key_id));',
           '        self.enter(sid)?;\n        let known = self.sessions.get(sid).is_some_and(|s| s.keys.contains(via_key_id));'),
    Mutant("SESSION-challenge-budget-shared", "I11f", "src/bridge.rs",
           """        let book = self.nonces.entry(sid.to_string()).or_default();
        if book.len() >= NONCE_RECORDS {
            // I11f: make room from spent or expired records only; a live
            // nonce is never evicted, so no caller can invalidate a nonce
            // another client holds. If every record is live, refuse.
            book.retain(|r| !r.used && issued - r.issued < t_nonce);
            if book.len() >= NONCE_RECORDS {""",
           """        let others: usize = self.nonces.iter().filter(|(k, _)| k.as_str() != sid).map(|(_, v)| v.len()).sum();
        let book = self.nonces.entry(sid.to_string()).or_default();
        if book.len() + others >= NONCE_RECORDS {
            // I11f: make room from spent or expired records only; a live
            // nonce is never evicted, so no caller can invalidate a nonce
            // another client holds. If every record is live, refuse.
            book.retain(|r| !r.used && issued - r.issued < t_nonce);
            if book.len() + others >= NONCE_RECORDS {"""),
    Mutant("SESSION-unauth-budget-restored-for-all", "I11g", "src/bridge.rs",
           "            self.unauth_logged.remove(sid); // a key holder spoke",
           "            self.unauth_logged.clear(); // a key holder spoke"),
    Mutant('SESSION-unauth-budget-shared', 'I11g', 'src/bridge.rs',
           '                let logged = self.unauth_logged.entry(sid.to_string()).or_insert(0);\n                if *logged >= UNAUTH_LOG_LIMIT {',
           '                let total: usize = self.unauth_logged.values().sum();\n                let logged = self.unauth_logged.entry(sid.to_string()).or_insert(0);\n                if total >= UNAUTH_LOG_LIMIT {'),
    Mutant("SESSION-revocation-requests-shared", "I11-REVOKE", "src/bridge.rs",
           "            let asked = self.revocation_requests.get(sid).copied().unwrap_or(0);",
           "            let asked: usize = self.revocation_requests.values().sum();"),
    Mutant("SESSION-revocation-requests-restored-for-all", "I11-REVOKE", "src/bridge.rs",
           "        self.revocation_requests.remove(sid);",
           "        self.revocation_requests.clear();"),
    Mutant("SESSION-forwarded-key-shared", "D", "src/bridge.rs",
           "            .filter(|(k, _)| !self.sent.contains(&(sid.to_string(), (*k).clone())))",
           "            .filter(|(k, _)| !self.sent.iter().any(|(_, sk)| sk == *k))"),
    Mutant('NONCE-binding-ignored', 'I11b', 'src/bridge.rs',
           '        let bound = rec.as_ref().is_some_and(|r| r.key_id == req.key_id && r.eligible);',
           '        let bound = rec.as_ref().is_some_and(|r| r.eligible);'),
    Mutant('NONCE-eligible-at-issue-ignored', 'I11b', 'src/bridge.rs',
           '                s.keys.contains(key_id) && !s.revoked.contains(key_id)\n',
           '                true\n'),
    Mutant('ADDCLIENT-binding-ignored', 'I15', 'src/bridge.rs',
           '        let bound = rec.as_ref().is_some_and(|r| r.key_id == via_key_id && r.eligible);',
           '        let bound = rec.as_ref().is_some_and(|r| r.eligible);'),
    Mutant('CHALLENGE-refuses-unregistered-key', 'I11', 'src/bridge.rs',
           '                s.keys.contains(key_id) && !s.revoked.contains(key_id)\n',
           '                if !s.keys.contains(key_id) {\n                    return Err(BridgeError::with_reason(CHALLENGE_REFUSED, "refused"));\n                }\n                !s.revoked.contains(key_id)\n'),
    Mutant('RESUME-in-progress-before-authentication', 'I11', 'src/bridge.rs',
           '        let mut reason = self.reject_reason(op, sid, &s, req)?;\n',
           '        let mut reason = self.reject_reason(op, sid, &s, req)?;\n        if s.cell.att == Attachment::Res {\n            reason = Some("resume_in_progress");\n        }\n'),
    Mutant('RESUME-same-tick-timer-not-awaited', 'L1', 'src/bridge.rs',
           '        self.check_timers_mode(sid, true)?;\n        self.refuse_unavailable(sid)?;',
           '        self.check_timers(sid)?;\n        self.refuse_unavailable(sid)?;'),
    Mutant('RESUME-transport-replay-spends-no-nonce', 'I8', 'src/bridge.rs',
           '        let mut reason = self.reject_reason(op, sid, &s, req)?;\n',
           '        let mut reason = if transport_replay { None } else { self.reject_reason(op, sid, &s, req)? };\n'),
    Mutant('RESUME-negative-seq-not-malformed', 'I4', 'src/bridge.rs',
           '        if req.seq < 0 || req.seq > (1i64 << 53) {',
           '        if false {'),
    Mutant('RESUME-revoked-key-refusal-always-logged', 'I11g', 'src/bridge.rs',
           '"transport_replay" | "unknown_key" | "bad_signature" | "nonce_binding" | "revoked_key"',
           '"transport_replay" | "unknown_key" | "bad_signature" | "nonce_binding"'),
    Mutant('REVOKE-soft-res-not-abandoned', 'I11-REVOKE', 'src/bridge.rs',
           'if (reason == "compromise" && last_connected) || verifying {',
           'if (reason == "compromise" && last_connected) || (verifying && reason == "compromise") {'),
    Mutant('REVOKE-repeated-revocation-accepted', 'I11-REVOKE', 'src/bridge.rs',
           '        if s.revoked.contains(key_id) {\n            return Err(BridgeError::with_reason(format!("key {key_id:?} is already revoked"), "revoked_key"));',
           '        if false {\n            return Err(BridgeError::with_reason(format!("key {key_id:?} is already revoked"), "revoked_key"));'),
    Mutant('OPERATOR-add-key-on-quarantined-session', 'I11-REVOKE', 'src/bridge.rs',
           '        if s.quarantined {\n            // rule Q: only a TERMINATION may follow the failure event',
           '        if false && s.quarantined {\n            // rule Q: only a TERMINATION may follow the failure event'),
    Mutant('CALL-direct-out-of-scope-forwarded', 'I3', 'src/bridge.rs',
           '            if permission.is_some_and(|p| !s.scope.iter().any(|x| x == p)) {',
           '            if false && permission.is_some_and(|p| !s.scope.iter().any(|x| x == p)) {'),
    Mutant('CALL-approval-boundary-inclusive', 'I13', 'src/bridge.rs',
           'c.approved_until.is_none_or(|u| now >= u)',
           'c.approved_until.is_none_or(|u| now > u)'),
    Mutant('CALL-approval-revived-by-later-resolution', 'I13', 'src/bridge.rs',
           'for c in s.queue.iter_mut().filter(|c| !c.held && c.approved_until.is_none()) {',
           'for c in s.queue.iter_mut().filter(|c| !c.held) {'),
    Mutant('CALL-generated-key-collides', 'I13', 'src/bridge.rs',
           '        while s.used_keys.contains(&format!("tc-{n:04}")) {',
           '        while false && s.used_keys.contains(&format!("tc-{n:04}")) {'),
    Mutant('CALL-completion-accepted-twice', 'I12', 'src/bridge.rs',
           '        if s.completed.contains(key) || !forwarded {',
           '        if !forwarded {'),
    Mutant('CALL-completion-of-unforwarded-call-accepted', 'I12', 'src/bridge.rs',
           '        if s.completed.contains(key) || !forwarded {',
           '        if s.completed.contains(key) {'),
    Mutant('SCOPE-recorded-as-presented', 'I10', 'src/bridge.rs',
           '"authority_scope": canonical_scope(&id.authority_scope),',
           '"authority_scope": id.authority_scope,'),
    Mutant('TIMER-reason-always-detach-timeout', 'L1', 'src/bridge.rs',
           'let away = if detach { "detach_timeout" } else { "detach_total_timeout" };',
           'let away = "detach_timeout";'),
    Mutant('NUMERICS-content-without-canonical-form-panics', 'I14', 'src/bridge.rs',
           '            if crate::wire::try_canonical_bytes(c).is_err() {',
           '            if false && crate::wire::try_canonical_bytes(c).is_err() {'),
    Mutant('CONFIG-infinite-timer-accepted', 'L1', 'src/types.rs',
           '            if !value.is_finite() || value < 0.0 {',
           '            if value.is_nan() || value < 0.0 {'),
    Mutant('WIRE-nesting-unbounded', 'WIRE', 'src/wire_server.rs',
           '        if nesting_depth(data) > MAX_DEPTH {',
           '        if false && nesting_depth(data) > MAX_DEPTH {'),
    Mutant('WIRE-revoke-request-not-authenticated', 'WIRE', 'src/wire_server.rs',
           '            && msg.get("requested_by").is_some())',
           '            && false)'),
    # I-CHECKPOINT
    Mutant('CP-no-emission', 'I-CHECKPOINT', 'src/bridge.rs',
           '        if since < self.cfg.n_checkpoint && (now - last) < self.cfg.t_checkpoint {',
           '        if true || since < self.cfg.n_checkpoint && (now - last) < self.cfg.t_checkpoint {'),
    Mutant('CP-wrong-root', 'I-CHECKPOINT', 'src/bridge.rs',
           '        let root = crate::merkle::merkle_root_hex(&hashes);',
           '        let root = crate::merkle::merkle_root_hex(&hashes[..hashes.len().saturating_sub(1)]);'),
    Mutant('CP-no-chain-check', 'I-CHECKPOINT', 'src/bridge.rs',
           '        let Ok(hashes) = self.chain_hashes(sid) else { return Ok(()) }; // not vouched for',
           '        let hashes = self.chain_hashes(sid).unwrap_or_default();'),
    Mutant('CP-on-terminated-or-quarantined', 'I-CHECKPOINT', 'src/bridge.rs',
           '        if s.cell.life == Life::Terminated || s.quarantined {\n            return Ok(());\n        }\n        let n = self.storage.read_log(sid)?.len();',
           '        let n = self.storage.read_log(sid)?.len();'),
    Mutant('CP-tracker-not-rebuilt', 'I-CHECKPOINT', 'src/bridge.rs',
           '            if let Some(i) = log.iter().rposition(|e| e.kind == Kind::CHECKPOINT) {\n                b.cp_len.insert(sid.clone(), i + 1);\n            }',
           ''),
]

# each unsigned op is asked of the authentication hook; dropping any of
# them from UNSIGNED_OPS leaves it unserved (resolve has its own mutant above).
_UNSIGNED_OPS = ["disconnect", "escalate", "resolve", "submit_tool_call",
                 "answer_tool_call", "delivered", "completed", "narrow",
                 "extend", "terminate"]
for _op in _UNSIGNED_OPS:
    if _op == "resolve":
        continue
    _kept = [o for o in _UNSIGNED_OPS if o != _op]
    MUTANTS.append(Mutant(
        f"WIRE-{_op.replace('_', '-')}-not-authenticated", "WIRE",
        "src/wire_server.rs",
        'pub const UNSIGNED_OPS: [&str; 10] = [\n'
        '    "disconnect", "escalate", "resolve", "submit_tool_call", "answer_tool_call",\n'
        '    "delivered", "completed", "narrow", "extend", "terminate",\n];',
        f'pub const UNSIGNED_OPS: [&str; 9] = [{", ".join(chr(34) + o + chr(34) for o in _kept)}];'))


def cargo_test(src: Path, target: Path) -> tuple[int, str]:
    env = dict(os.environ, CARGO_TARGET_DIR=str(target))
    p = subprocess.run(["cargo", "test", "--quiet"], cwd=src, env=env,
                       capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--only")
    a = ap.parse_args()
    if shutil.which("cargo") is None:
        print("cargo not found", file=sys.stderr)
        return 2
    bad = 0
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        target = Path(os.environ.get("MUTATION_TARGET_DIR") or tmp / "target")
        shutil.copytree(VECTORS, tmp / "vectors", copy_function=shutil.copyfile)
        work = tmp / "rust-bridge"
        ignore = shutil.ignore_patterns("target")
        # copyfile gives every file a new modification time, so a build kept in
        # MUTATION_TARGET_DIR is never taken for current by a copy with older mtimes
        shutil.copytree(CRATE, work, ignore=ignore, copy_function=shutil.copyfile)
        rc, out = cargo_test(work, target)
        if rc != 0:
            print("unmutated crate fails:\n" + out[-2000:], file=sys.stderr)
            return 1
        # Control: the patch path with a patch that changes nothing must pass.
        ctl = MUTANTS[0]
        orig = (CRATE / ctl.file).read_text()
        if orig.count(ctl.old) != 1:
            print("control: anchor does not apply once", file=sys.stderr)
            return 1
        (work / ctl.file).write_text(orig.replace(ctl.old, ctl.old))
        try:
            rc, out = cargo_test(work, target)
        finally:
            (work / ctl.file).write_text(orig)
        if rc != 0:
            print("control (a patch that changes nothing) fails; the harness "
                  "is not sound:\n" + out[-2000:], file=sys.stderr)
            return 1
        killed = 0
        ran = 0
        for m in MUTANTS:
            if a.only and m.name != a.only:
                continue
            ran += 1
            path = work / m.file
            orig = (CRATE / m.file).read_text()
            if orig.count(m.old) != 1:
                print(f"PATCH-ERROR (anchor found {orig.count(m.old)}x) {m.rule:11s} {m.name}")
                bad += 1
                continue
            path.write_text(orig.replace(m.old, m.new))
            try:
                rc, out = cargo_test(work, target)
            finally:
                path.write_text(orig)
            if rc == 0:
                print(f"SURVIVED  {m.rule:11s} {m.name}")
                bad += 1
            elif rc == 101 and "test result: FAILED" in out and "could not compile" not in out:
                failing = sorted(set(re.findall(r"^---- (\S+) stdout ----", out, re.M)))
                shown = ",".join(failing[:4]) + ("..." if len(failing) > 4 else "")
                if set(failing) <= STORAGE_ONLY:
                    # a kill by the file-storage test alone says the mutant
                    # breaks the fixture, not a rule of the contract
                    print(f"NOT-KILLED-BY-A-RULE-TEST {m.rule:11s} {m.name}  <- {shown}")
                    bad += 1
                    continue
                print(f"killed    {m.rule:11s} {m.name}  <- {shown}")
                killed += 1
            else:
                print(f"ERROR (exit {rc}, not a test failure) {m.rule:11s} {m.name}\n{out[-600:]}")
                bad += 1
    print(f"\n{killed}/{ran} Rust mutants killed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
