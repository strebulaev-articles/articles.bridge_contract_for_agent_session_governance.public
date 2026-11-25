//! Wire-format helpers for the Bridge Contract client--bridge protocol.
//!
//! Mirrors `wire.py` in the Python supplementary. The wire format is
//! specified normatively in Appendix B of the paper.
//!
//! Canonicalisation is RFC 8785 (JCS) for the value types the contract
//! uses: strings (raw UTF-8, RFC 8785 escapes), integers up to 2^53, finite
//! floats (ECMAScript number formatting, `1.0` is `1`), arrays, and objects
//! sorted by the UTF-16 code units of their names. NaN, infinities and
//! integers beyond 2^53 have no portable form and are refused. The bytes
//! are pinned by `../vectors/bytes_kat.json`, which the Python runner reads
//! too.

use serde_json::{json, Map, Value};

const MAX_SAFE_INT: u64 = 1 << 53;

/// RFC 8785 canonical JSON of `obj`, or the reason it has none.
pub fn try_canonical_bytes(obj: &Value) -> Result<Vec<u8>, String> {
    let mut out = String::new();
    emit(obj, &mut out)?;
    Ok(out.into_bytes())
}

/// RFC 8785 canonical JSON encoding of `obj`.
///
/// Used for: (a) the signature input of every signed op; (b) the
/// wire-encoding of any message before it is sent; (c) event and content
/// hashes. Panics on a value with no canonical form (see
/// [`try_canonical_bytes`]).
pub fn canonical_bytes(obj: &Value) -> Vec<u8> {
    try_canonical_bytes(obj).expect("value has an RFC 8785 canonical form")
}

fn emit(v: &Value, out: &mut String) -> Result<(), String> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                if u > MAX_SAFE_INT {
                    return Err("integer beyond 2^53 is not portable".into());
                }
                out.push_str(&u.to_string());
            } else if let Some(i) = n.as_i64() {
                if i.unsigned_abs() > MAX_SAFE_INT {
                    return Err("integer beyond 2^53 is not portable".into());
                }
                out.push_str(&i.to_string());
            } else {
                out.push_str(&es6_number(n.as_f64().ok_or("number has no f64 form")?)?);
            }
        }
        Value::String(s) => string(s, out),
        Value::Array(arr) => {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                emit(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut members: Vec<(&String, &Value)> = map.iter().collect();
            members.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.push('{');
            for (i, (k, v)) in members.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                string(k, out);
                out.push(':');
                emit(v, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// RFC 8785 section 3.2.2.2: short escapes for `"` `\` and `\b \t \n \f \r`,
/// lower-case `\u00xx` for other controls, everything else raw.
fn string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// ECMAScript `Number.prototype.toString` for a finite double (RFC 8785
/// section 3.2.2.3).
fn es6_number(x: f64) -> Result<String, String> {
    if !x.is_finite() {
        return Err("NaN and infinities have no canonical form".into());
    }
    if x == 0.0 {
        return Ok("0".into());
    }
    let sign = if x < 0.0 { "-" } else { "" };
    // shortest round-trip digits d.ddd and a decimal exponent
    let sci = format!("{:e}", x.abs());
    let (mant, exp) = sci.split_once('e').ok_or("unexpected float format")?;
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let n: i32 = exp.parse::<i32>().map_err(|e| e.to_string())? + 1;
    let k = digits.len() as i32;
    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let es = format!("{}{}", if e >= 0 { "+" } else { "-" }, e.abs());
        if k > 1 {
            format!("{}.{}e{es}", &digits[..1], &digits[1..])
        } else {
            format!("{digits}e{es}")
        }
    };
    Ok(format!("{sign}{body}"))
}

/// The signature input: canonical JSON of a JSON array.
///
/// The signed op-types sign over:
/// - `attach`: `["bc/v1/attach", bridge_id, session_id, principal, scope,
///   lineage, key_id, scheme, public_key]` (see [`crate::attach_message`])
/// - `add_client`: `["bc/v1/add-client", session_id, via_key_id, new_key_id,
///   scheme, new_public_key, nonce]` (see [`crate::add_client_message`])
/// - `reattach` / `join`: `["bc/v1/reattach" | "bc/v1/join", session_id,
///   key_id, nonce, seq, hash]` (see [`crate::request_message`])
pub fn canonical_for_signature(values: &[Value]) -> Vec<u8> {
    canonical_bytes(&Value::Array(values.to_vec()))
}

/// Encode a client->bridge request as canonical JSON bytes.
pub fn encode_message(op: &str, session_id: Option<&str>, fields: &Map<String, Value>) -> Vec<u8> {
    let mut msg = Map::new();
    msg.insert("op".to_string(), Value::String(op.to_string()));
    if let Some(sid) = session_id {
        msg.insert("session_id".to_string(), Value::String(sid.to_string()));
    }
    for (k, v) in fields {
        msg.insert(k.clone(), v.clone());
    }
    canonical_bytes(&Value::Object(msg))
}

/// Decode a client->bridge request from bytes.
pub fn decode_message(data: &[u8]) -> std::result::Result<Value, String> {
    let obj: Value = serde_json::from_slice(data)
        .map_err(|e| format!("invalid JSON: {}", e))?;
    if !obj.is_object() {
        return Err("wire message must be a JSON object".to_string());
    }
    if obj.get("op").is_none() {
        return Err("wire message must have an 'op' field".to_string());
    }
    Ok(obj)
}

/// Encode a bridge->client response as canonical JSON bytes.
pub fn encode_response(status: &str, session_id: Option<&str>, fields: &Map<String, Value>) -> Vec<u8> {
    let mut msg = Map::new();
    msg.insert("status".to_string(), Value::String(status.to_string()));
    if let Some(sid) = session_id {
        msg.insert("session_id".to_string(), Value::String(sid.to_string()));
    }
    for (k, v) in fields {
        msg.insert(k.clone(), v.clone());
    }
    canonical_bytes(&Value::Object(msg))
}

/// Decode a bridge->client response from bytes.
pub fn decode_response(data: &[u8]) -> std::result::Result<Value, String> {
    let obj: Value = serde_json::from_slice(data)
        .map_err(|e| format!("invalid JSON: {}", e))?;
    if !obj.is_object() {
        return Err("wire response must be a JSON object".to_string());
    }
    if obj.get("status").is_none() {
        return Err("wire response must have a 'status' field".to_string());
    }
    Ok(obj)
}

/// Encode a bridge->client error response as canonical JSON bytes.
pub fn encode_error(session_id: &str, reason: &str) -> Vec<u8> {
    canonical_bytes(&json!({
        "status": "rejected",
        "session_id": session_id,
        "reason": reason,
    }))
}

// --- op-type constructors --------------------------------------------------
//
// Each constructor builds the canonical request bytes for one op-type.
// The signature, where required, is computed by the caller and passed
// in; these helpers do not sign.

/// `grant` or `signature` of `None` is left out of the message (a request
/// that carries none), which the bridge refuses.
pub fn op_attach(session_id: &str, principal: &str, scope: &[&str], lineage: &[&str],
                 key_id: &str, scheme: &str, public_key: &str, grant: Option<&str>,
                 signature: Option<&str>) -> Vec<u8> {
    let mut fields = Map::new();
    fields.insert("principal".into(), json!(principal));
    fields.insert("scope".into(), json!(scope));
    fields.insert("lineage".into(), json!(lineage));
    fields.insert("key_id".into(), json!(key_id));
    fields.insert("scheme".into(), json!(scheme));
    fields.insert("public_key".into(), json!(public_key));
    if let Some(g) = grant {
        fields.insert("grant".into(), json!(g));
    }
    if let Some(sig) = signature {
        fields.insert("signature".into(), json!(sig));
    }
    encode_message("attach", Some(session_id), &fields)
}

pub fn op_add_client(session_id: &str, via_key_id: &str, new_key_id: &str, scheme: &str,
                     new_public_key: &str, nonce: &str, signature: &str) -> Vec<u8> {
    let mut fields = Map::new();
    fields.insert("via_key_id".into(), json!(via_key_id));
    fields.insert("new_key_id".into(), json!(new_key_id));
    fields.insert("scheme".into(), json!(scheme));
    fields.insert("new_public_key".into(), json!(new_public_key));
    fields.insert("nonce".into(), json!(nonce));
    fields.insert("signature".into(), json!(signature));
    encode_message("add_client", Some(session_id), &fields)
}

/// A challenge names the key id the nonce is for; the bridge binds the
/// nonce to it and answers the same way for any key id.
pub fn op_challenge(session_id: &str, key_id: &str) -> Vec<u8> {
    let mut f = Map::new();
    f.insert("key_id".into(), json!(key_id));
    encode_message("challenge", Some(session_id), &f)
}

pub fn op_reattach(session_id: &str, key_id: &str, nonce: &str, seq: u64,
                   hash: &str, signature: &str) -> Vec<u8> {
    let mut fields = Map::new();
    fields.insert("key_id".into(), json!(key_id));
    fields.insert("nonce".into(), json!(nonce));
    fields.insert("seq".into(), json!(seq));
    fields.insert("hash".into(), json!(hash));
    fields.insert("signature".into(), json!(signature));
    encode_message("reattach", Some(session_id), &fields)
}

pub fn op_join(session_id: &str, key_id: &str, nonce: &str, seq: u64,
               hash: &str, signature: &str) -> Vec<u8> {
    let mut fields = Map::new();
    fields.insert("key_id".into(), json!(key_id));
    fields.insert("nonce".into(), json!(nonce));
    fields.insert("seq".into(), json!(seq));
    fields.insert("hash".into(), json!(hash));
    fields.insert("signature".into(), json!(signature));
    encode_message("join", Some(session_id), &fields)
}

pub fn op_disconnect(session_id: &str, reason: &str, key_id: Option<&str>) -> Vec<u8> {
    let mut fields = Map::new();
    fields.insert("reason".into(), json!(reason));
    if let Some(kid) = key_id {
        fields.insert("key_id".into(), json!(kid));
    }
    encode_message("disconnect", Some(session_id), &fields)
}

pub fn op_escalate(session_id: &str, trigger: Option<&str>) -> Vec<u8> {
    let mut fields = Map::new();
    if let Some(t) = trigger {
        fields.insert("trigger".into(), json!(t));
    }
    encode_message("escalate", Some(session_id), &fields)
}

pub fn op_resolve(session_id: &str) -> Vec<u8> {
    encode_message("resolve", Some(session_id), &Map::new())
}

pub fn op_submit_tool_call(session_id: &str, tool: &str, content: &Value,
                           key: Option<&str>, permission: Option<&str>) -> Vec<u8> {
    let mut fields = Map::new();
    fields.insert("tool".into(), json!(tool));
    fields.insert("content".into(), content.clone());
    if let Some(k) = key {
        fields.insert("key".into(), json!(k));
    }
    if let Some(p) = permission {
        fields.insert("permission".into(), json!(p));
    }
    encode_message("submit_tool_call", Some(session_id), &fields)
}

pub fn op_answer_tool_call(session_id: &str, key: &str, shown_hash: &str,
                           decision: &str) -> Vec<u8> {
    let mut fields = Map::new();
    fields.insert("key".into(), json!(key));
    fields.insert("shown_hash".into(), json!(shown_hash));
    fields.insert("decision".into(), json!(decision));
    encode_message("answer_tool_call", Some(session_id), &fields)
}

pub fn op_delivered(session_id: &str, key: &str) -> Vec<u8> {
    let mut fields = Map::new();
    fields.insert("key".into(), json!(key));
    encode_message("delivered", Some(session_id), &fields)
}

pub fn op_completed(session_id: &str, key: &str, result_hash: Option<&str>) -> Vec<u8> {
    let mut fields = Map::new();
    fields.insert("key".into(), json!(key));
    if let Some(rh) = result_hash {
        fields.insert("result_hash".into(), json!(rh));
    }
    encode_message("completed", Some(session_id), &fields)
}

pub fn op_narrow(session_id: &str, new_scope: &[&str]) -> Vec<u8> {
    let mut fields = Map::new();
    fields.insert("new_scope".into(), json!(new_scope));
    encode_message("narrow", Some(session_id), &fields)
}

pub fn op_extend(session_id: &str, new_scope: &[&str], source: &str) -> Vec<u8> {
    let mut fields = Map::new();
    fields.insert("new_scope".into(), json!(new_scope));
    fields.insert("source".into(), json!(source));
    encode_message("extend", Some(session_id), &fields)
}

pub fn op_terminate(session_id: &str, reason: &str) -> Vec<u8> {
    let mut fields = Map::new();
    fields.insert("reason".into(), json!(reason));
    encode_message("terminate", Some(session_id), &fields)
}

/// An operator revocation; `signature` is the operator's over
/// `["bc/v1/revoke", bridge_id, sid, key_id, reason, seq, head]`. With
/// `requested_by` and an empty signature it is only a request.
pub fn op_revoke(session_id: &str, key_id: &str, reason: &str, signature: Option<&str>,
                 requested_by: Option<&str>) -> Vec<u8> {
    let mut fields = Map::new();
    fields.insert("key_id".into(), json!(key_id));
    fields.insert("reason".into(), json!(reason));
    if let Some(sig) = signature {
        fields.insert("signature".into(), json!(sig));
    }
    if let Some(by) = requested_by {
        fields.insert("requested_by".into(), json!(by));
    }
    encode_message("revoke", Some(session_id), &fields)
}

/// An operator key addition to a key_exhausted session.
pub fn op_add_key(session_id: &str, key_id: &str, scheme: &str, public_key: &str,
                  signature: Option<&str>) -> Vec<u8> {
    let mut fields = Map::new();
    fields.insert("key_id".into(), json!(key_id));
    fields.insert("scheme".into(), json!(scheme));
    fields.insert("public_key".into(), json!(public_key));
    if let Some(sig) = signature {
        fields.insert("signature".into(), json!(sig));
    }
    encode_message("add_key", Some(session_id), &fields)
}

/// An operator termination of a key_exhausted session.
pub fn op_operator_terminate(session_id: &str, reason: &str, signature: Option<&str>) -> Vec<u8> {
    let mut fields = Map::new();
    fields.insert("reason".into(), json!(reason));
    if let Some(sig) = signature {
        fields.insert("signature".into(), json!(sig));
    }
    encode_message("operator_terminate", Some(session_id), &fields)
}

pub fn op_tick(session_id: Option<&str>) -> Vec<u8> {
    encode_message("tick", session_id, &Map::new())
}

pub fn op_restart() -> Vec<u8> {
    encode_message("restart", None, &Map::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_bytes_deterministic() {
        let a = json!({"b": 1, "a": 2});
        let b = json!({"a": 2, "b": 1});
        assert_eq!(canonical_bytes(&a), canonical_bytes(&b));
    }

    #[test]
    fn test_canonical_for_signature() {
        let values = vec![json!("sess-001"), json!("nonce123"), json!(6), json!("abc")];
        let sig = canonical_for_signature(&values);
        assert_eq!(sig, br#"["sess-001","nonce123",6,"abc"]"#.to_vec());
    }

    #[test]
    fn test_attach_and_add_client_carry_the_scheme() {
        let a = op_attach("s", "p", &["a"], &["l"], "k", "ecdsa-p256", "ab", Some("g"), Some("cd"));
        let d = decode_message(&a).unwrap();
        assert_eq!(d["op"], "attach");
        assert_eq!(d["scheme"], "ecdsa-p256");
        assert_eq!(d["public_key"], "ab");
        assert_eq!(canonical_bytes(&d), a);
        let c = op_add_client("s", "k", "k2", "ecdsa-p256", "ab", "n", "cd");
        assert_eq!(decode_message(&c).unwrap()["scheme"], "ecdsa-p256");
    }

    #[test]
    fn test_challenge_roundtrip() {
        let msg = op_challenge("sess-001", "ck-1");
        let decoded = decode_message(&msg).unwrap();
        assert_eq!(decoded["op"], "challenge");
        assert_eq!(decoded["session_id"], "sess-001");
    }

    #[test]
    fn test_reattach_roundtrip() {
        let msg = op_reattach("sess-001", "ck-1", "n1", 6, "h1", "sig");
        let decoded = decode_message(&msg).unwrap();
        assert_eq!(decoded["op"], "reattach");
        assert_eq!(decoded["key_id"], "ck-1");
        assert_eq!(decoded["seq"], 6);
    }

    #[test]
    fn test_error_encoding() {
        let err = encode_error("sess-001", "prefix_mismatch");
        let decoded = decode_response(&err).unwrap();
        assert_eq!(decoded["status"], "rejected");
        assert_eq!(decoded["reason"], "prefix_mismatch");
    }

    #[test]
    fn test_restart_no_session_id() {
        let msg = op_restart();
        let decoded = decode_message(&msg).unwrap();
        assert_eq!(decoded["op"], "restart");
        assert!(decoded.get("session_id").is_none());
    }

    #[test]
    fn test_disconnect_optional_key() {
        let msg = op_disconnect("sess-001", "client_disconnect", None);
        let decoded = decode_message(&msg).unwrap();
        assert!(decoded.get("key_id").is_none());
    }

    #[test]
    fn test_response_encoding() {
        let mut fields = Map::new();
        fields.insert("events".into(), json!([{"sequence": 7}]));
        let resp = encode_response("verified", Some("sess-001"), &fields);
        let decoded = decode_response(&resp).unwrap();
        assert_eq!(decoded["status"], "verified");
        assert_eq!(decoded["events"][0]["sequence"], 7);
    }
}
